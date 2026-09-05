import re

from src.coverage.registry import UnsupportedCommandFamily


def _family(
    family_id: str,
    pattern: str,
    rationale: str,
) -> UnsupportedCommandFamily:
    return UnsupportedCommandFamily(
        family_id=family_id,
        pattern=re.compile(pattern),
        rationale=rationale,
    )


# Executable source of truth for declared, analyzer-scope Cisco gaps.
# These patterns classify only parser-produced unparsed lines. They do not
# normalize state or interpret block semantics.
UNSUPPORTED_COMMAND_FAMILIES = (
    _family(
        "trunk_native_vlan",
        r"^switchport trunk native vlan\b.+$",
        "Trunk VLAN exposure context.",
    ),
    _family(
        "trunk_allowed_vlan",
        r"^switchport trunk allowed vlan\b.+$",
        "Trunk VLAN exposure context.",
    ),
    _family(
        "port_security_subcommand",
        (
            r"^switchport port-security "
            r"(?:maximum|violation|mac-address|aging)\b.*$"
        ),
        "Unsupported Port Security policy detail.",
    ),
    _family(
        "dhcp_snooping_rate",
        r"^ip dhcp snooping limit rate\b.*$",
        "Unsupported DHCP Snooping rate policy.",
    ),
    _family(
        "dhcp_snooping_information",
        r"^(?:no )?ip dhcp snooping information option\b.*$",
        "Unsupported DHCP Snooping option policy.",
    ),
    _family(
        "dai_trust",
        r"^ip arp inspection trust$",
        "Unsupported DAI trust state.",
    ),
    _family(
        "dai_rate",
        r"^ip arp inspection limit rate\b.*$",
        "Unsupported DAI rate policy.",
    ),
    _family(
        "dai_validate",
        r"^ip arp inspection validate\b.*$",
        "Unsupported DAI validation policy.",
    ),
    _family(
        "dai_filter",
        r"^ip arp inspection filter\b.*$",
        "Unsupported DAI filter policy.",
    ),
    _family(
        "ip_source_guard_variant",
        r"^(?:no )?ip verify source\s+.+$",
        "Unsupported IP Source Guard variant.",
    ),
    _family(
        "http_authentication",
        r"^ip http authentication\b.*$",
        "Unsupported HTTP authentication policy.",
    ),
    _family(
        "http_access_restriction",
        r"^ip http access-class\b.*$",
        "Unsupported HTTP access restriction.",
    ),
    _family(
        "snmp",
        r"^snmp-server\b.*$",
        "Declared SNMP management-plane gap.",
    ),
    _family(
        "aaa",
        r"^aaa\b.*$",
        "Declared AAA management-plane authentication gap.",
    ),
    _family(
        "lldp_receive",
        r"^(?:no )?lldp receive$",
        "LLDP receive is separate from advertisement and remains unmodeled.",
    ),
    _family(
        "root_guard",
        r"^spanning-tree guard root$",
        "Declared STP Root Guard gap.",
    ),
    _family(
        "vty_transport_variant",
        r"^transport input\s+.+$",
        "Known management transport syntax not normalized by the parser.",
    ),
)


OUT_OF_SCOPE_PATTERNS = (
    re.compile(r"^(?:end|exit)$"),
)


def match_unsupported_family(command: str) -> UnsupportedCommandFamily | None:
    return next(
        (
            family
            for family in UNSUPPORTED_COMMAND_FAMILIES
            if family.pattern.fullmatch(command)
        ),
        None,
    )


def is_out_of_scope(command: str) -> bool:
    return any(pattern.fullmatch(command) for pattern in OUT_OF_SCOPE_PATTERNS)


class CiscoCoverageRegistry:
    @staticmethod
    def match_unsupported_family(
        command: str,
    ) -> UnsupportedCommandFamily | None:
        return match_unsupported_family(command)

    @staticmethod
    def is_out_of_scope(command: str) -> bool:
        return is_out_of_scope(command)
