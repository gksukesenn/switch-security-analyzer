from dataclasses import dataclass, field
from enum import Enum


class ConfigState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    NOT_CONFIGURED = "not_configured"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"


class InterfaceMode(str, Enum):
    ACCESS = "access"
    TRUNK = "trunk"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class SourceLine:
    line_number: int
    text: str


@dataclass
class InterfaceConfig:
    name: str

    description: str | None = None

    mode: InterfaceMode = InterfaceMode.UNKNOWN
    access_vlan: int | None = None

    dhcp_snooping_trust: ConfigState = ConfigState.NOT_CONFIGURED
    port_security: ConfigState = ConfigState.NOT_CONFIGURED
    portfast: ConfigState = ConfigState.NOT_CONFIGURED
    bpdu_guard: ConfigState = ConfigState.NOT_CONFIGURED

    raw_lines: list[SourceLine] = field(default_factory=list)


@dataclass
class ParsedConfig:
    vendor: str

    hostname: str | None = None

    dhcp_snooping_global: ConfigState = ConfigState.NOT_CONFIGURED
    dhcp_snooping_global_evidence: SourceLine | None = None

    dhcp_snooping_vlans: set[int] = field(default_factory=set)
    dhcp_snooping_vlan_evidence: dict[int, SourceLine] = field(
        default_factory=dict)

    portfast_default: ConfigState = ConfigState.NOT_CONFIGURED
    portfast_default_evidence: SourceLine | None = None

    bpdu_guard_default: ConfigState = ConfigState.NOT_CONFIGURED
    bpdu_guard_default_evidence: SourceLine | None = None

    interfaces: list[InterfaceConfig] = field(default_factory=list)

    unparsed_lines: list[SourceLine] = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str

    severity: Severity
    confidence: Confidence

    technical_impact: str
    remediation: str
    safe_config_example: str

    evidence: list[SourceLine] = field(default_factory=list)
    affected_interfaces: list[str] = field(default_factory=list)
