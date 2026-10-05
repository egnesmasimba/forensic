"""Backwards-compatible alias for the libpcap capture engine.

The live libpcap/Npcap binding now lives in :mod:`network_sensor.engines` so the
libpcap, PF_RING and DPDK backends share one interface contract. This module
keeps the original ``Pcap`` name working for existing callers.
"""
from __future__ import annotations

from .engines import LibpcapEngine, npcap_folder, npcap_installed, npcap_version
from .packets import CaptureError

#: Original name of the libpcap adapter.
Pcap = LibpcapEngine

__all__ = ["Pcap", "LibpcapEngine", "CaptureError", "npcap_folder", "npcap_installed", "npcap_version"]