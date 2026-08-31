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


class CoverageClass(str, Enum):
    SUPPORTED_RELEVANT = "supported_relevant"
    UNSUPPORTED_RELEVANT = "unsupported_relevant"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN_RELEVANCE = "unknown_relevance"


class AnalysisConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SourceLine:
    line_number: int
    text: str


@dataclass
class InterfaceConfig:
    name: str

    declaration_evidence: SourceLine | None = None

    description: str | None = None

    mode: InterfaceMode = InterfaceMode.UNKNOWN
    mode_evidence: SourceLine | None = None
    access_vlan: int | None = None
    access_vlan_evidence: SourceLine | None = None

    dhcp_snooping_trust: ConfigState = ConfigState.NOT_CONFIGURED
    port_security: ConfigState = ConfigState.NOT_CONFIGURED
    portfast: ConfigState = ConfigState.NOT_CONFIGURED
    bpdu_guard: ConfigState = ConfigState.NOT_CONFIGURED
    ip_source_guard: ConfigState = ConfigState.NOT_CONFIGURED

    dhcp_snooping_trust_evidence: SourceLine | None = None
    port_security_evidence: SourceLine | None = None
    portfast_evidence: SourceLine | None = None
    bpdu_guard_evidence: SourceLine | None = None
    ip_source_guard_evidence: SourceLine | None = None

    raw_lines: list[SourceLine] = field(default_factory=list)


@dataclass
class VtyConfig:
    start: int
    end: int

    declaration_evidence: SourceLine | None = None

    # ENABLED means an explicit, non-empty transport directive was fully
    # normalized; it does not mean the management configuration is secure.
    transport_input_state: ConfigState = ConfigState.NOT_CONFIGURED
    transport_input: set[str] = field(default_factory=set)
    transport_input_evidence: SourceLine | None = None

    raw_lines: list[SourceLine] = field(default_factory=list)


@dataclass
class ParsedConfig:
    vendor: str

    hostname: str | None = None

    dhcp_snooping_global: ConfigState = ConfigState.NOT_CONFIGURED
    dhcp_snooping_global_evidence: SourceLine | None = None

    http_server: ConfigState = ConfigState.NOT_CONFIGURED
    http_server_evidence: SourceLine | None = None

    https_server: ConfigState = ConfigState.NOT_CONFIGURED
    https_server_evidence: SourceLine | None = None

    dhcp_snooping_vlans: set[int] = field(default_factory=set)
    dhcp_snooping_vlan_evidence: dict[int, SourceLine] = field(
        default_factory=dict)

    dai_vlans: set[int] = field(default_factory=set)
    dai_vlan_evidence: dict[int, SourceLine] = field(
        default_factory=dict)

    portfast_default: ConfigState = ConfigState.NOT_CONFIGURED
    portfast_default_evidence: SourceLine | None = None

    bpdu_guard_default: ConfigState = ConfigState.NOT_CONFIGURED
    bpdu_guard_default_evidence: SourceLine | None = None

    interfaces: list[InterfaceConfig] = field(default_factory=list)
    vty_lines: list[VtyConfig] = field(default_factory=list)

    unparsed_lines: list[SourceLine] = field(default_factory=list)
    parsed_line_coverage: dict[int, CoverageClass] = field(
        default_factory=dict
    )


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


@dataclass(frozen=True)
class RuleEvaluation:
    findings: list[Finding]
    assessed_units: int
