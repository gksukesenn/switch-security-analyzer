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
        "dynamic_endpoint_vlan",
        (
            r"^(?:no )?(?:aaa port-access (?:authenticator|mac-based)"
            r"(?:\s+\S.*)?|aaa authentication port-access "
            r"(?:local|eap-radius|chap-radius)(?:\s+.*)?)$"
        ),
        "Unsupported dynamic 802.1X or MAC-auth endpoint VLAN policy.",
    ),
    _family(
        "port_security",
        r"^(?:no )?port-security(?:\s+\S.*)?$",
        "Unsupported AOS-S Port Security policy.",
    ),
    _family(
        "source_lockdown",
        (
            r"^(?:no )?(?:ip source-lockdown\s+\S+|"
            r"ip source-binding\s+\S+\s+vlan\s+\d+\s+\S+\s+"
            r"interface\s+\S+)$"
        ),
        "Unsupported IP Source Lockdown policy or static binding.",
    ),
    _family(
        "stp_edge_bpdu_protection",
        (
            r"^(?:no )?spanning-tree\s+\S+\s+"
            r"(?:admin-edge-port|auto-edge-port|bpdu-protection)$"
        ),
        "Unsupported AOS-S STP edge or BPDU-protection state.",
    ),
    _family(
        "management_service",
        (
            r"^(?:no )?(?:telnet-server|web-management(?:\s+ssl)?|"
            r"ip ssh(?:\s+filetransfer)?)$"
        ),
        "Unsupported Telnet, web-management, or SSH service state.",
    ),
    _family(
        "arp_protect_trust",
        r"^(?:no )?arp-protect trust\s+\S.*$",
        "Unsupported AOS-S Dynamic ARP Protection trust state.",
    ),
    _family(
        "dhcp_snooping_extended_control",
        (
            r"^(?:no )?dhcp-snooping (?:"
            r"authorized-server\s+\S+|database\s+\S+|"
            r"option\s+82(?:\s+\S.*)?|rate-limit\s+\S.*|"
            r"verify(?:\s+\S.*)?)$"
        ),
        (
            "Unsupported DHCP Snooping server, binding, Option 82, rate, "
            "or verification control."
        ),
    ),
)

OUT_OF_SCOPE_PATTERNS = (re.compile(r"^(?:exit|end)$"),)


class ArubaAOSSCoverageRegistry:
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
