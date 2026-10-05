"""Capture engine abstraction with libpcap/Npcap, PF_RING and DPDK backends.

Each backend opens a passive read-only handle and yields the same four-field
record the pipeline consumes: (timestamp, frame bytes, original length, link
type). No backend injects, modifies or replays traffic.

Backend selection is explicit. A backend whose native library, kernel module or
hugepage environment is absent raises CaptureError naming the missing
prerequisite rather than silently falling back to libpcap, so a deployment never
believes it is running on PF_RING or DPDK when it is not.
"""
from __future__ import annotations

import ctypes as ct
import ctypes.util
import os
import platform
import time
from pathlib import Path

from .packets import CaptureError

BACKENDS = ("libpcap", "pfring", "dpdk")
DEFAULT_BACKEND = "libpcap"
MAX_SNAPSHOT = 65535
SUPPORTED_LINKTYPES = (1, 101, 113, 276)  # Ethernet, raw IP, Linux cooked v1, v2
ZERO_TIMESTAMP = object()  # Sentinel returned when a backend has no usable clock.


class CaptureEngine:
    """Common interface implemented by every live capture backend."""

    name = "none"

    def devices(self) -> list[dict]:
        raise NotImplementedError

    def open(self, interface: str, bpf: str = "tcp or udp", promiscuous: bool = True):
        raise NotImplementedError

    def next_packet(self):
        """Return (timestamp, frame, original_length, linktype) or None when idle."""
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    def statistics(self) -> dict:
        return {"available": False}

    @property
    def linktype(self) -> int:
        raise NotImplementedError

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class _Timeval(ct.Structure):
    _fields_ = [("seconds", ct.c_long), ("microseconds", ct.c_long)]


class _PacketHeader(ct.Structure):
    _fields_ = [("timestamp", _Timeval), ("caplen", ct.c_uint32), ("length", ct.c_uint32)]


class _Device(ct.Structure):
    pass


_Device._fields_ = [("next", ct.POINTER(_Device)), ("name", ct.c_char_p), ("description", ct.c_char_p),
                    ("addresses", ct.c_void_p), ("flags", ct.c_uint32)]


class _BpfProgram(ct.Structure):
    _fields_ = [("length", ct.c_uint), ("instructions", ct.c_void_p)]


class _CaptureStats(ct.Structure):
    # WinPcap/Npcap extend the first three fields; the remainder is padding.
    _fields_ = [("received", ct.c_uint32), ("dropped", ct.c_uint32), ("interface_dropped", ct.c_uint32),
                ("extensions", ct.c_uint32 * 8)]


def npcap_folder() -> Path:
    return Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "Npcap"


def npcap_installed() -> bool:
    return (npcap_folder() / "wpcap.dll").is_file()


def npcap_version() -> str:
    """Read the installed Npcap/WinPcap version, or return an explanatory marker."""
    if not npcap_installed():
        return "not installed"
    directory = os.add_dll_directory(str(npcap_folder()))
    try:
        wpcap = ct.CDLL(str(npcap_folder() / "wpcap.dll"))
        wpcap.pcap_lib_version.restype = ct.c_char_p
        return wpcap.pcap_lib_version().decode(errors="replace")
    except OSError as error:  # Missing dependency DLL, or a 32/64-bit mismatch.
        return f"unavailable ({error})"
    finally:
        directory.close()


def check_linktype(linktype: int, backend: str = "libpcap") -> int:
    if linktype not in SUPPORTED_LINKTYPES:
        raise CaptureError(f"{backend} reported unsupported link type {linktype}")
    return linktype


class LibpcapEngine(CaptureEngine):
    """Windows Npcap / Unix libpcap adapter. The portable default backend."""

    name = "libpcap"

    def __init__(self):
        self.dll_directory = None
        if os.name == "nt":
            if not npcap_installed():
                raise CaptureError(
                    "Npcap is not installed. Install the official Npcap driver before live capture.")
            self.dll_directory = os.add_dll_directory(str(npcap_folder()))
            library = str(npcap_folder() / "wpcap.dll")
        else:
            library = ctypes.util.find_library("pcap")
            if not library:
                raise CaptureError("libpcap is not installed")
        try:
            self.lib = ct.CDLL(library)
        except OSError as error:
            raise CaptureError(f"Cannot load the libpcap library: {error}") from error
        self._bind()
        self.handle = None

    def _bind(self):
        signatures = {
            "pcap_findalldevs": ([ct.POINTER(ct.POINTER(_Device)), ct.c_char_p], ct.c_int),
            "pcap_freealldevs": ([ct.POINTER(_Device)], None),
            "pcap_open_live": ([ct.c_char_p, ct.c_int, ct.c_int, ct.c_int, ct.c_char_p], ct.c_void_p),
            "pcap_close": ([ct.c_void_p], None),
            "pcap_datalink": ([ct.c_void_p], ct.c_int),
            "pcap_setnonblock": ([ct.c_void_p, ct.c_int, ct.c_char_p], ct.c_int),
            "pcap_next_ex": ([ct.c_void_p, ct.POINTER(ct.POINTER(_PacketHeader)),
                              ct.POINTER(ct.POINTER(ct.c_ubyte))], ct.c_int),
            "pcap_compile": ([ct.c_void_p, ct.POINTER(_BpfProgram), ct.c_char_p, ct.c_int, ct.c_uint32], ct.c_int),
            "pcap_setfilter": ([ct.c_void_p, ct.POINTER(_BpfProgram)], ct.c_int),
            "pcap_freecode": ([ct.POINTER(_BpfProgram)], None),
            "pcap_geterr": ([ct.c_void_p], ct.c_char_p),
            "pcap_stats": ([ct.c_void_p, ct.POINTER(_CaptureStats)], ct.c_int),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.lib, name)
            function.argtypes, function.restype = args, result

    def devices(self) -> list[dict]:
        first = ct.POINTER(_Device)()
        error = ct.create_string_buffer(256)
        if self.lib.pcap_findalldevs(ct.byref(first), error) != 0:
            raise CaptureError(error.value.decode(errors="replace"))
        result = []
        try:
            pointer = first
            while pointer:
                item = pointer.contents
                result.append({"name": item.name.decode(errors="replace"),
                               "description": (item.description or b"").decode(errors="replace")})
                pointer = item.next
        finally:
            self.lib.pcap_freealldevs(first)
        return result

    def open(self, interface, bpf="tcp or udp", promiscuous=True):
        error = ct.create_string_buffer(256)
        self.handle = self.lib.pcap_open_live(interface.encode(), MAX_SNAPSHOT, int(promiscuous), 100, error)
        if not self.handle:
            raise CaptureError(error.value.decode(errors="replace"))
        try:
            self._linktype = check_linktype(self.lib.pcap_datalink(self.handle), self.name)
            if self.lib.pcap_setnonblock(self.handle, 1, error) != 0:
                raise CaptureError(error.value.decode(errors="replace"))
            program = _BpfProgram()
            if self.lib.pcap_compile(self.handle, ct.byref(program), bpf.encode(), 1, 0xFFFFFFFF) != 0:
                raise CaptureError(self.lib.pcap_geterr(self.handle).decode(errors="replace"))
            try:
                if self.lib.pcap_setfilter(self.handle, ct.byref(program)) != 0:
                    raise CaptureError(self.lib.pcap_geterr(self.handle).decode(errors="replace"))
            finally:
                self.lib.pcap_freecode(ct.byref(program))
        except Exception:
            self.close()
            raise
        return self

    def next_packet(self):
        header, data = ct.POINTER(_PacketHeader)(), ct.POINTER(ct.c_ubyte)()
        status = self.lib.pcap_next_ex(self.handle, ct.byref(header), ct.byref(data))
        if status == 0:
            return None
        if status < 0:
            raise CaptureError(self.lib.pcap_geterr(self.handle).decode(errors="replace"))
        item = header.contents
        if item.caplen > MAX_SNAPSHOT:
            raise CaptureError("Capture exceeds snapshot length")
        return (item.timestamp.seconds + item.timestamp.microseconds / 1e6,
                ct.string_at(data, item.caplen), item.length, self._linktype)

    def close(self):
        if getattr(self, "handle", None):
            self.lib.pcap_close(self.handle)
            self.handle = None

    def statistics(self) -> dict:
        stats = _CaptureStats()
        if not getattr(self, "handle", None) or self.lib.pcap_stats(self.handle, ct.byref(stats)) != 0:
            return {"available": False}
        return {"available": True, "received": stats.received, "dropped": stats.dropped,
                "interface_dropped": stats.interface_dropped}

    @property
    def linktype(self) -> int:
        return self._linktype


# -- PF_RING ------------------------------------------------------------------

PF_RING_VERSION = 6
PF_RING_PROMISC = 1 << 15
PF_RING_NO_BUFFER = 1 << 5
PF_RING_ZEROCOPY = 1 << 12
PF_RING_EXT_TIMESTAMP = 1 << 26


class _PfringHeader(ct.Structure):
    # struct pfring_pkthdr: timeval, caplen, len, extended_hdr, pkt_offset.
    _fields_ = [("timestamp", _Timeval), ("caplen", ct.c_uint32), ("len", ct.c_uint32),
                ("extended_hdr", ct.c_void_p), ("pkt_offset", ct.c_uint16)]


class PfRingEngine(CaptureEngine):
    """Linux PF_RING backend. Requires the pf_ring kernel module and libpfring.

    PF_RING timestamps come from the kernel in nanoseconds; they are converted
    here so downstream consumers see the same seconds-as-float contract as
    libpcap. A zero timestamp (hardware timestamping unavailable) is reported
    rather than replaced with wall-clock time, which would falsify capture time.
    """

    name = "pfring"

    def __init__(self):
        if os.name == "nt":
            raise CaptureError("PF_RING runs on Linux only; use the libpcap backend on Windows")
        library = ctypes.util.find_library("pfring") or "libpfring.so"
        try:
            self.lib = ct.CDLL(library)
        except OSError as error:
            raise CaptureError(f"Cannot load libpfring: {error}. Install PF_RING from ntop.org") from error
        self._bind()
        self.ring = None
        self._linktype = 1
        self._stats = [0, 0, 0, 0, 0, 0, 0]

    def _bind(self):
        signatures = {
            "pfring_init": ([ct.c_uint32, ct.c_uint32, ct.c_uint32, ct.c_void_p, ct.c_void_p], ct.c_int),
            "pfring_open": ([ct.c_void_p], ct.c_int),
            "pfring_close": ([ct.c_void_p], None),
            "pfring_enable_ring": ([ct.c_void_p], ct.c_int),
            "pfring_break_loop": ([ct.c_void_p], None),
            "pfring_set_application_name": ([ct.c_void_p, ct.c_char_p], None),
            "pfring_set_promisc": ([ct.c_void_p], ct.c_int),
            "pfring_recv": ([ct.c_void_p, ct.POINTER(ct.POINTER(ct.c_ubyte)), ct.c_uint, ct.c_void_p,
                             ct.c_uint8, ct.POINTER(ct.c_uint32)], ct.c_int),
            "pfring_compile_filter": ([ct.c_void_p, ct.c_char_p, ct.POINTER(ct.c_uint32)], ct.c_int),
            "pfring_set_filter": ([ct.c_void_p, ct.c_char_p, ct.c_uint32], ct.c_int),
            "pfring_free_filter": ([ct.c_void_p, ct.c_char_p], None),
            "pfring_get_stats": ([ct.c_void_p, ct.POINTER(ct.c_uint64)], ct.c_int),
            "pfring_version_ext_pcap_get_link_type": ([ct.c_void_p], ct.c_int),
            "pfring_get_interface_list": ([ct.c_char_p, ct.c_uint], ct.c_int),
            "pfring_open_interface": ([ct.c_void_p, ct.c_char_p, ct.c_void_p, ct.c_uint32], ct.c_int),
            "pfring_error": ([ct.c_char_p], None),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.lib, name)
            function.argtypes, function.restype = args, result

    def devices(self) -> list[dict]:
        if not Path("/proc/net/pf_ring").is_dir():
            raise CaptureError("The pf_ring kernel module is not loaded (no /proc/net/pf_ring)")
        result = []
        for entry in Path("/proc/net/pf_ring").iterdir():
            result.append({"name": entry.name, "description": f"PF_RING {entry.name}"})
        return result

    def open(self, interface, bpf="tcp or udp", promiscuous=True):
        flags = PF_RING_NO_BUFFER if not promiscuous else 0
        if self.lib.pfring_init(PF_RING_VERSION, 0, flags, ct.byref(self.ring), None) != 0:
            raise CaptureError("pfring_init failed; confirm the pf_ring module is loaded")
        try:
            if self.lib.pfring_open(self.ring) != 0:
                raise CaptureError("pfring_open failed")
            self.lib.pfring_set_application_name(self.ring, b"efmtt-sensor")
            self._linktype = check_linktype(
                self.lib.pfring_version_ext_pcap_get_link_type(self.ring), self.name)
            if promiscuous and self.lib.pfring_set_promisc(self.ring) != 0:
                raise CaptureError("PF_RING could not enable promiscuous mode on this interface")
            if self.lib.pfring_enable_ring(self.ring) != 0:
                raise CaptureError("pfring_enable_ring failed")
            if bpf and bpf != "tcp or udp":
                length = ct.c_uint32(1024)
                expression = ct.create_string_buffer(bpf.encode())
                if self.lib.pfring_compile_filter(self.ring, expression, ct.byref(length)) != 0:
                    raise CaptureError("PF_RING could not compile the capture filter")
                try:
                    if self.lib.pfring_set_filter(self.ring, expression, length) != 0:
                        raise CaptureError("PF_RING could not apply the capture filter")
                finally:
                    self.lib.pfring_free_filter(self.ring, expression)
        except Exception:
            self.close()
            raise
        return self

    def next_packet(self):
        buffer, header, page = ct.POINTER(ct.c_ubyte)(), _PfringHeader(), ct.c_uint32()
        status = self.lib.pfring_recv(self.ring, ct.byref(buffer), MAX_SNAPSHOT, ct.byref(header), 1, ct.byref(page))
        if status < 0:
            raise CaptureError(f"pfring_recv failed: {status}")
        if status == 0:
            return None
        item = header.contents
        if item.caplen > MAX_SNAPSHOT:
            raise CaptureError("Capture exceeds snapshot length")
        raw = ct.string_at(buffer, item.caplen)
        seconds = item.timestamp.seconds + item.timestamp.microseconds / 1e6
        # PF_RING reports zero when the kernel could not timestamp the packet.
        timestamp = seconds if seconds > 0 else ZERO_TIMESTAMP
        return (timestamp, raw, item.len, self._linktype)

    def close(self):
        if getattr(self, "ring", None):
            self.lib.pfring_break_loop(self.ring)
            self.lib.pfring_close(self.ring)
            self.ring = None

    def statistics(self) -> dict:
        if not getattr(self, "ring", None):
            return {"available": False}
        values = (ct.c_uint64 * 7)()
        if self.lib.pfring_get_stats(self.ring, ct.byref(values)) != 0:
            return {"available": False}
        return {"available": True, "received": values[0], "dropped": values[1],
                "interface_dropped": values[2]}

    @property
    def linktype(self) -> int:
        return self._linktype


# -- DPDK ---------------------------------------------------------------------

RTE_MAX_LANES = 16
RTE_ETH_RX_OFFLOAD_CHECKSUM = 0x08
RTE_ETH_MQ_RX_RSS = 0x4
DPDK_ARGUMENT_LIMIT = 64


class _DpdkEalArgs(ct.Structure):
    _fields_ = [("argc", ct.c_int), ("argv", ct.c_void_p)]


class DpdkEngine(CaptureEngine):
    """Linux DPDK poll-mode backend for high-rate mirror/tap capture.

    DPDK is initialised once per process with EAL arguments supplied by the
    deployment; rte_eal_init may only run a single time, so a second engine in
    the same process reuses the existing EAL and creates its own rx queue.

    The mbuf struct is read through declared offsets rather than a full
    definition: the buffer address and length fields are the documented first
    members and are stable across the supported releases. If a future release
    changes them, the produced frame bytes are validated against the Ethernet
    minimum size, which fails loudly rather than writing plausible-looking
    garbage into the recording.
    """

    name = "dpdk"
    _MBMAP_BUFFER_ADDR = 0
    _MBMAP_DATA_LEN = 42
    _MBUF_STRIDE = 128

    def __init__(self, eal_args: list[str] | None = None, queue_id: int = 0,
                 pool_size: int = 8192, cache_size: int = 256, rx_descriptors: int = 1024,
                 data_room_size: int = 2176):
        if os.name == "nt":
            raise CaptureError("DPDK runs on Linux only; use the libpcap backend on Windows")
        if not self._probe_hugepages():
            raise CaptureError(
                "DPDK needs hugepages. Mount a hugetlbfs page pool (for example "
                "'mount -t hugetlbfs nodev /dev/hugepages') or use dpdk-hugepages --make-nodev.")
        self.queue_id = int(queue_id)
        self.pool_size, self.cache_size = int(pool_size), int(cache_size)
        self.rx_descriptors, self.data_room_size = int(rx_descriptors), int(data_room_size)
        self.eal_args = self._validate_eal(eal_args)
        self._initialise_eal()
        self.port = None
        self.mempool = None
        self.started = False
        self._burst = (ct.c_void_p * RTE_MAX_LANES)()
        self._linktype = 1
        self._rx_missed = 0
        self._rx_packets = 0

    @staticmethod
    def _probe_hugepages() -> bool:
        if Path("/sys/kernel/mm/hugepages").is_dir():
            try:
                return any(int(item.name.split("-")[0]) >= 0
                           for item in Path("/sys/kernel/mm/hugepages").iterdir())
            except (OSError, ValueError):
                return True
        return False

    @staticmethod
    def _validate_eal(eal_args) -> list[str]:
        if not eal_args:
            return []
        if len(eal_args) > DPDK_ARGUMENT_LIMIT:
            raise CaptureError("DPDK EAL arguments are limited")
        for argument in eal_args:
            # EAL arguments reach a native parser; keep them to short printable text.
            if not isinstance(argument, str) or len(argument) > 256 or not argument.isprintable():
                raise CaptureError("DPDK EAL arguments must be short printable strings")
        return list(eal_args)

    def _initialise_eal(self):
        library = ctypes.util.find_library("dpdk") or "librte_eal.so.23"
        try:
            self.eal = ct.CDLL(library)
        except OSError:
            self.eal = ct.CDLL("librte_eal.so")
        self.eal.rte_eal_init.argtypes = [ct.POINTER(_DpdkEalArgs)]
        self.eal.rte_eal_init.restype = ct.c_int
        self.eal.rte_eal_cleanup.argtypes = []
        self.eal.rte_eal_cleanup.restype = None
        if getattr(self, "_eal_ready", False):
            return  # EAL is process-wide and already initialised by an earlier engine.
        arguments = self.eal_args or ["-l", "0", "-n", "1"]
        buffer = (ct.c_char_p * (len(arguments) + 1))()
        for index, argument in enumerate(arguments):
            buffer[index] = argument.encode()
        holder = _DpdkEalArgs(len(arguments), ct.cast(buffer, ct.c_void_p))
        result = self.eal.rte_eal_init(ct.byref(holder))
        if result < 0:
            raise CaptureError(f"rte_eal_init failed with {result}; check hugepages, EAL arguments and driver binding")
        self._eal_ready = True

    def _load_ethdev(self):
        library = ctypes.util.find_library("dpdk") or "librte_ethdev.so.23"
        try:
            self.ethdev = ct.CDLL(library)
        except OSError:
            self.ethdev = ct.CDLL("librte_ethdev.so")
        ethdev_signatures = (
            ("rte_eth_dev_count_avail", [], ct.c_uint),
            ("rte_eth_dev_by_name", [ct.c_char_p], ct.c_void_p),
            ("rte_eth_dev_get_name_by_port", [ct.c_uint, ct.c_void_p, ct.c_uint], ct.c_char_p),
            ("rte_eth_rx_queue_setup", [ct.c_void_p, ct.c_uint16, ct.c_uint16, ct.c_uint16,
                                        ct.c_void_p, ct.c_void_p, ct.c_uint64, ct.c_uint64], ct.c_int),
            ("rte_eth_dev_start", [ct.c_void_p], ct.c_int),
            ("rte_eth_dev_stop", [ct.c_void_p], ct.c_int),
            ("rte_eth_dev_close", [ct.c_void_p], None),
            ("rte_eth_rx_burst", [ct.c_void_p, ct.c_uint16, ct.POINTER(ct.c_void_p), ct.c_uint16], ct.c_uint16),
            ("rte_eth_stats_get", [ct.c_void_p, ct.c_void_p], ct.c_int),
        )
        for name, args, result in ethdev_signatures:
            function = getattr(self.ethdev, name, None)
            if function is None:
                raise CaptureError(f"This DPDK build does not export {name}")
            function.argtypes, function.restype = args, result
        try:
            self.mempool_api = ct.CDLL("librte_mempool.so.23")
            self.mbuf_api = ct.CDLL("librte_mbuf.so.23")
        except OSError:
            self.mempool_api = ct.CDLL("librte_mempool.so")
            self.mbuf_api = ct.CDLL("librte_mbuf.so")
        self.mempool_api.rte_pktmbuf_pool_create.argtypes = [
            ct.c_void_p, ct.c_uint, ct.c_uint, ct.c_uint, ct.c_int, ct.c_uint, ct.c_int]
        self.mempool_api.rte_pktmbuf_pool_create.restype = ct.c_void_p
        self.mbuf_api.rte_pktmbuf_alloc.argtypes = [ct.c_void_p, ct.c_uint]
        self.mbuf_api.rte_pktmbuf_alloc.restype = ct.c_void_p
        self.mbuf_api.rte_pktmbuf_free.argtypes = [ct.c_void_p]
        self.mbuf_api.rte_pktmbuf_free.restype = None

    def devices(self) -> list[dict]:
        self._load_ethdev()
        buffer = (ct.c_char * 64)()
        result = []
        for port in range(self.ethdev.rte_eth_dev_count_avail()):
            name = self.ethdev.rte_eth_dev_get_name_by_port(port, ct.byref(buffer), 64)
            text = (name or b"").decode(errors="replace") or f"dpdk-port-{port}"
            result.append({"name": text, "description": f"DPDK ethdev port {port}"})
        return result

    def open(self, interface, bpf="tcp or udp", promiscuous=True):
        self._load_ethdev()
        self.port = self.ethdev.rte_eth_dev_by_name(interface.encode())
        if not self.port:
            raise CaptureError(
                f"DPDK has no ethdev named {interface}; bind a driver with dpdk-devbind and confirm rte_eal_init")
        self._linktype = 1
        name = (ct.c_char * 64)()
        name.value = interface.encode()[:63]
        self.mempool = self.mempool_api.rte_pktmbuf_pool_create(
            name, self.pool_size, self.cache_size, 0, -1, self.data_room_size, 0)
        if not self.mempool:
            raise CaptureError("rte_pktmbuf_pool_create failed; check the mempool size and hugepage pool")
        if self.ethdev.rte_eth_rx_queue_setup(self.port, self.queue_id, self.rx_descriptors, 0,
                                              self.mempool, None, 0, 0) != 0:
            self._release()
            raise CaptureError("rte_eth_rx_queue_setup failed; the port may not support this queue configuration")
        if self.ethdev.rte_eth_dev_start(self.port) != 0:
            self._release()
            raise CaptureError("rte_eth_dev_start failed")
        self.started = True
        return self

    def next_packet(self):
        count = self.ethdev.rte_eth_rx_burst(self.port, self.queue_id, self._burst, RTE_MAX_LANES)
        if not count:
            return None
        pointer = self._burst[0]
        raw = ct.string_at(pointer + self._MBMAP_BUFFER_ADDR, self._data_len(pointer))
        self._rx_packets += 1
        for index in range(1, count):
            self.mbuf_api.rte_pktmbuf_free(self._burst[index])
        self.mbuf_api.rte_pktmbuf_free(pointer)
        # DPDK does not timestamp in the rx path by default; report the sentinel.
        return (ZERO_TIMESTAMP, raw, len(raw), self._linktype)

    def _data_len(self, pointer) -> int:
        length = ct.c_uint16.from_address(pointer + self._MBMAP_DATA_LEN).value
        if length < 14 or length > MAX_SNAPSHOT:
            # An implausible length means the mbuf layout assumption no longer
            # holds for this DPDK release; fail instead of recording garbage.
            raise CaptureError(
                f"DPDK returned an implausible frame length ({length}); this build's rte_mbuf layout is unsupported")
        return length

    def close(self):
        if getattr(self, "started", False):
            self.ethdev.rte_eth_dev_stop(self.port)
            self.started = False
        if getattr(self, "port", None):
            self.ethdev.rte_eth_dev_close(self.port)
            self.port = None

    def _release(self):
        self.close()
        self.mempool = None

    def statistics(self) -> dict:
        # struct rte_eth_stats is an array of uint64: ipackets, opackets, ierrors, ...
        stats = (ct.c_uint64 * 16)()
        if not getattr(self, "port", None) or self.ethdev.rte_eth_stats_get(self.port, ct.byref(stats)) != 0:
            return {"available": False}
        return {"available": True, "received": stats[0], "transmitted": stats[1],
                "errors": stats[2], "rx_missed": self._rx_missed}

    @property
    def linktype(self) -> int:
        return self._linktype


BACKEND_CLASSES = {"libpcap": LibpcapEngine, "pfring": PfRingEngine, "dpdk": DpdkEngine}


def create_engine(backend: str = DEFAULT_BACKEND, eal_args: list[str] | None = None) -> CaptureEngine:
    if backend not in BACKENDS:
        raise CaptureError(f"Unknown capture backend {backend}; choose one of {', '.join(BACKENDS)}")
    factory = BACKEND_CLASSES[backend]
    return factory(eal_args) if backend == "dpdk" else factory()


def describe_backend(backend: str) -> dict:
    """Report whether a backend can run here, without raising."""
    if backend not in BACKENDS:
        raise CaptureError(f"Unknown capture backend {backend}")
    detail = {
        "libpcap": {"platform": "Windows and Linux", "library": "Npcap wpcap.dll" if os.name == "nt" else "libpcap",
                    "note": "Portable default; promiscuous mode requires a mirror/SPAN port or tap"},
        "pfring": {"platform": "Linux", "library": "libpfring",
                   "note": "Requires the pf_ring kernel module and /proc/net/pf_ring"},
        "dpdk": {"platform": "Linux", "library": "librte_eal / librte_ethdev",
                 "note": "Requires hugepages, a bound driver, and EAL arguments supplied by the deployment"},
    }[backend]
    try:
        engine = create_engine(backend)
        available, error = True, ""
        engine.close()
    except CaptureError as failure:
        available, error = False, str(failure)
    return {"backend": backend, "available": available, "error": error, **detail,
            "host": platform.platform(), "processor": platform.machine()}


def available_backends() -> list[dict]:
    return [describe_backend(name) for name in BACKENDS]


def normalise_timestamp(record, fallback_clock=time.time):
    """Replace the zero-timestamp sentinel with an explicitly labelled clock source.

    DPDK and PF_RING may deliver untimestamped packets. Substituting wall-clock
    time silently would fabricate capture times, so the sentinel is preserved and
    the caller is told which clock was used.
    """
    timestamp, frame, length, linktype = record
    if timestamp is ZERO_TIMESTAMP:
        return fallback_clock(), frame, length, linktype, "host_clock_substituted"
    return timestamp, frame, length, linktype, "capture_clock"
