import pytest

from src.coverage.aruba_aos_s_registry import ArubaAOSSCoverageRegistry
from src.domain.models import CoverageClass
from src.parsers.aruba.aos_s import ArubaAOSSParser
from src.services.coverage import CoverageService


@pytest.mark.parametrize(
    ("command", "family_id"),
    [
        ("aaa port-access authenticator 1 auth-vid 10", "dynamic_endpoint_vlan"),
        ("aaa port-access mac-based 2 unauth-vid 20", "dynamic_endpoint_vlan"),
        ("port-security 1 learn-mode static", "port_security"),
        ("ip source-lockdown 1-4", "source_lockdown"),
        (
            "ip source-binding 001122-334455 vlan 10 192.0.2.2 interface 1",
            "source_lockdown",
        ),
        ("spanning-tree 1-4 admin-edge-port", "stp_edge_bpdu_protection"),
        ("spanning-tree 1-4 bpdu-protection", "stp_edge_bpdu_protection"),
        ("telnet-server", "management_service"),
        ("web-management ssl", "management_service"),
        ("ip ssh", "management_service"),
        ("arp-protect trust 24", "arp_protect_trust"),
        (
            "dhcp-snooping authorized-server 192.0.2.10",
            "dhcp_snooping_extended_control",
        ),
        (
            "dhcp-snooping option 82 untrusted-policy drop",
            "dhcp_snooping_extended_control",
        ),
        (
            "dhcp-snooping rate-limit 100 1-4",
            "dhcp_snooping_extended_control",
        ),
        (
            "dhcp-snooping database tftp://192.0.2.1/bindings",
            "dhcp_snooping_extended_control",
        ),
    ],
)
def test_aos_s_registry_classifies_narrow_unsupported_families(
    command,
    family_id,
):
    family = ArubaAOSSCoverageRegistry().match_unsupported_family(command)

    assert family is not None
    assert family.family_id == family_id


def test_aos_s_unknown_security_looking_syntax_remains_unknown():
    raw_text = "security-policy experimental endpoint-vlan 10\n"
    report = CoverageService(
        parser=ArubaAOSSParser(),
        registry=ArubaAOSSCoverageRegistry(),
    ).evaluate(raw_text)

    assert report.lines[0].classification == CoverageClass.UNKNOWN_RELEVANCE
    assert report.lines[0].family_id is None


@pytest.mark.parametrize("command", ["exit", "end"])
def test_aos_s_registry_classifies_verified_structural_lines(command):
    assert ArubaAOSSCoverageRegistry().is_out_of_scope(command)


def test_aos_s_registry_does_not_broadly_allow_structural_looking_syntax():
    assert not ArubaAOSSCoverageRegistry().is_out_of_scope("interface 1")
