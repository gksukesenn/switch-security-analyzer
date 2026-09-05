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


UNSUPPORTED_COMMAND_FAMILIES = (
    _family(
        "interface_dhcp_snooping",
        r"^dhcp snooping enable$",
        "Unsupported interface-scoped DHCP Snooping state.",
    ),
    _family(
        "dhcp_snooping_disable",
        r"^dhcp snooping disable$",
        "Unsupported explicit DHCP Snooping disable form.",
    ),
    _family(
        "dhcp_snooping_extended_control",
        (
            r"^(?:undo )?dhcp snooping (?:"
            r"check\s+\S+(?:\s+\S+)*|"
            r"rate-limit\s+\S+(?:\s+\S+)*|"
            r"user-bind\s+\S+(?:\s+\S+)*)$"
        ),
        "Unsupported DHCP Snooping check, rate, or binding control.",
    ),
    _family(
        "dai_user_bind",
        r"^(?:undo )?arp anti-attack check user-bind(?:\s+\S+)*$",
        "Unsupported interface- or VLAN-scoped DAI state.",
    ),
    _family(
        "ip_source_check_user_bind",
        r"^(?:undo )?ip source check user-bind(?:\s+\S+)*$",
        "Unsupported Huawei IP source validation state.",
    ),
    _family(
        "port_security",
        r"^(?:undo )?port-security(?:\s+\S.*)?$",
        "Unsupported Huawei Port Security policy.",
    ),
    _family(
        "hybrid_vlan_membership",
        (
            r"^port hybrid (?:pvid vlan\s+\d+|"
            r"(?:tagged|untagged) vlan\s+\S+(?:\s+\S+)*)$"
        ),
        "Unsupported hybrid PVID or VLAN membership.",
    ),
    _family(
        "trunk_vlan_scope",
        r"^port trunk allow-pass vlan\s+\S+(?:\s+\S+)*$",
        "Unsupported trunk allowed-VLAN scope.",
    ),
    _family(
        "stp_protection",
        (
            r"^(?:undo )?stp (?:root-protection|loop-protection|"
            r"bpdu-filter(?:\s+enable)?)$"
        ),
        "Unsupported interface STP protection family.",
    ),
    _family(
        "telnet_management",
        r"^(?:undo )?telnet server (?:enable|disable)$",
        "Unsupported Telnet management service state.",
    ),
    _family(
        "http_management",
        (
            r"^(?:undo )?http (?:server enable|secure-server enable|"
            r"server-source\s+\S+(?:\s+\S+)*)$"
        ),
        "Unsupported HTTP management service or source restriction.",
    ),
)

OUT_OF_SCOPE_PATTERNS = (re.compile(r"^(?:quit|return)$"),)


class HuaweiVRPCoverageRegistry:
    @staticmethod
    def match_unsupported_family(
        command: str,
    ) -> UnsupportedCommandFamily | None:
        return next(
            (
                family
                for family in UNSUPPORTED_COMMAND_FAMILIES
                if family.pattern.fullmatch(command)
            ),
            None,
        )

    @staticmethod
    def is_out_of_scope(command: str) -> bool:
        return any(
            pattern.fullmatch(command)
            for pattern in OUT_OF_SCOPE_PATTERNS
        )
