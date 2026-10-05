from pydantic import BaseModel, ConfigDict, Field, field_validator

from .engines import BACKENDS
from .protocols import PROTOCOLS


class CapturePointConfig(BaseModel):
    """Describes the physical tap or SPAN/mirror port feeding the sensor."""

    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    interface: str = Field(min_length=1, max_length=128)
    source: str = Field(default="mirror", pattern=r"^(mirror|tap)$")
    layer_1: bool = True
    layer_2: bool = False
    vlan_ids: list[int] = Field(default_factory=list, max_length=256)
    notes: str = Field(default="", max_length=512)

    @field_validator("vlan_ids")
    @classmethod
    def vlans_valid(cls, values):
        if any(not 1 <= value <= 4094 for value in values):
            raise ValueError("VLAN IDs must be 1-4094; 0 and 4095 are reserved")
        return sorted(dict.fromkeys(values))


class SensorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocols: list[str] = Field(default_factory=lambda: list(PROTOCOLS), min_length=1, max_length=30)
    port_map: dict[str, str] = Field(default_factory=dict)
    queue_capacity: int = Field(default=512, ge=1, le=4096)
    max_sessions: int = Field(default=256, ge=1, le=256)
    bytes_per_direction: int = Field(default=65536, ge=1024, le=65536)
    session_idle_seconds: int = Field(default=300, ge=1, le=86400)
    session_max_seconds: int = Field(default=3600, ge=1, le=604800)
    closed_session_grace_seconds: int = Field(default=5, ge=0, le=300)
    max_completed_sessions: int = Field(default=256, ge=1, le=256)
    malware_ips: list[str] = Field(default_factory=list, max_length=1000)
    c2_ips: list[str] = Field(default_factory=list, max_length=1000)
    heavy_bytes: int = Field(default=1048576, ge=1)
    iso_field_lengths: dict[str, int] = Field(default_factory=dict)

    @field_validator("iso_field_lengths")
    @classmethod
    def iso_widths(cls, values):
        cleaned = {}
        for key, width in values.items():
            number = int(key)
            if not 2 <= number <= 128 or number == 1 or not 1 <= int(width) <= 32:
                raise ValueError("ISO field lengths name a data field and a width of 1 to 32")
            cleaned[str(number)] = int(width)
        return cleaned

    @field_validator("malware_ips", "c2_ips")
    @classmethod
    def valid_indicators(cls, values):
        from ipaddress import ip_address
        return sorted({str(ip_address(value)) for value in values})

    bpf: str = Field(default="tcp or udp", min_length=1, max_length=1024)
    promiscuous: bool = True
    backend: str = Field(default="libpcap")
    capture_point: CapturePointConfig | None = None
    eal_args: list[str] = Field(default_factory=list, max_length=64)
    encryption_key_id: str | None = Field(default=None, min_length=1, max_length=64)
    encryption_keyring: str | None = Field(default=None, max_length=1024)
    encryption_context: str = Field(default="network-sensor", min_length=1, max_length=128)
    idle_seconds: int = Field(default=60, ge=1, le=86400)
    empty_seconds: int = Field(default=30, ge=1, le=86400)
    backlog_ratio: float = Field(default=0.8, gt=0, le=1)
    min_disk_bytes: int = Field(default=134217728, ge=0)
    analytics_server_url: str | None = None
    analytics_agent_token_env: str = Field(default="ZANAQ_ANALYTICS_AGENT_TOKEN", pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    analytics_subject: str = Field(default="network-sensor", min_length=1, max_length=120)
    analytics_ca_bundle: str | None = None
    snmp_host: str | None = None
    snmp_port: int = Field(default=162, ge=1, le=65535)
    snmp_community_env: str = "EFMTT_SNMP_COMMUNITY"
    snmp_enterprise_oid: str = "1.3.6.1.4.1.32473.1"

    @field_validator("protocols")
    @classmethod
    def protocols_known(cls, values):
        if any(value not in PROTOCOLS for value in values):
            raise ValueError("Unknown protocol selection")
        return list(dict.fromkeys(values))

    @field_validator("backend")
    @classmethod
    def backend_known(cls, value):
        if value not in BACKENDS:
            raise ValueError(f"Capture backend must be one of {', '.join(BACKENDS)}")
        return value

    @field_validator("eal_args")
    @classmethod
    def eal_args_safe(cls, values):
        for argument in values:
            if not argument.isprintable() or len(argument) > 256:
                raise ValueError("DPDK EAL arguments must be short printable strings")
        return list(values)

    @field_validator("encryption_keyring")
    @classmethod
    def keyring_is_path(cls, value):
        if value is None:
            return None
        if any(character in value for character in "\0\n"):
            raise ValueError("Keyring path contains control characters")
        return value

    def capture_filter(self) -> str:
        """Append the configured VLAN allow-list to the BPF filter."""
        vlans = self.capture_point.vlan_ids if self.capture_point else []
        if not vlans:
            return self.bpf
        clauses = " or ".join(f"vlan {value}" for value in vlans)
        return f"(({self.bpf}) and ({clauses}))"

    @property
    def encryption_enabled(self) -> bool:
        return bool(self.encryption_key_id and self.encryption_keyring)

    @field_validator("port_map")
    @classmethod
    def ports_known(cls, mapping):
        if len(mapping) > 100 or any(not port.isdecimal() or not 1 <= int(port) <= 65535 or protocol not in PROTOCOLS for port, protocol in mapping.items()):
            raise ValueError("Port mappings require ports 1–65535 and supported protocol names")
        return {str(int(port)): protocol for port, protocol in mapping.items()}
