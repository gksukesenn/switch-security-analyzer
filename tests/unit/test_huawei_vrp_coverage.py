import pytest

from src.coverage.huawei_vrp_registry import HuaweiVRPCoverageRegistry
from src.domain.models import CoverageClass
from src.parsers.huawei.vrp import HuaweiVRPParser
from src.services.coverage import CoverageService


@pytest.mark.parametrize(
    ("command", "family_id"),
    [
        ("dhcp snooping enable", "interface_dhcp_snooping"),
        ("dhcp snooping disable", "dhcp_snooping_disable"),
        (
            "dhcp snooping rate-limit 100",
            "dhcp_snooping_extended_control",
        ),
        (
            "dhcp snooping check dhcp-chaddr enable",
            "dhcp_snooping_extended_control",
        ),
        (
            "dhcp snooping user-bind static ip-address 192.0.2.10",
            "dhcp_snooping_extended_control",
        ),
        (
            "arp anti-attack check user-bind enable",
            "dai_user_bind",
        ),
        (
            "ip source check user-bind enable",
            "ip_source_check_user_bind",
        ),
        ("port-security enable", "port_security"),
        ("port hybrid pvid vlan 70", "hybrid_vlan_membership"),
        (
            "port hybrid tagged vlan 10 20",
            "hybrid_vlan_membership",
        ),
        (
            "port hybrid untagged vlan 70",
            "hybrid_vlan_membership",
        ),
        ("port trunk allow-pass vlan 10 20", "trunk_vlan_scope"),
        ("stp root-protection", "stp_protection"),
        ("stp loop-protection", "stp_protection"),
        ("stp bpdu-filter enable", "stp_protection"),
        ("telnet server enable", "telnet_management"),
        ("http server enable", "http_management"),
        ("http server-source -i Vlanif1", "http_management"),
    ],
)
def test_huawei_registry_matches_verified_unsupported_families(
    command,
    family_id,
):
    family = HuaweiVRPCoverageRegistry().match_unsupported_family(command)

    assert family is not None
    assert family.family_id == family_id


def test_interface_dhcp_enable_is_unsupported_but_global_is_parser_owned():
    raw_text = """dhcp snooping enable
interface GigabitEthernet0/0/1
 dhcp snooping enable
#
"""
    report = CoverageService(
        parser=HuaweiVRPParser(),
        registry=HuaweiVRPCoverageRegistry(),
    ).evaluate(raw_text)

    assert report.lines[0].classification == CoverageClass.SUPPORTED_RELEVANT
    assert report.lines[2].classification == CoverageClass.UNSUPPORTED_RELEVANT
    assert report.lines[2].family_id == "interface_dhcp_snooping"
    assert report.lines[3].classification == CoverageClass.OUT_OF_SCOPE


def test_unrelated_huawei_syntax_remains_unknown_relevance():
    report = CoverageService(
        parser=HuaweiVRPParser(),
        registry=HuaweiVRPCoverageRegistry(),
    ).evaluate("traffic-filter inbound acl 3000\n")

    assert report.lines[0].classification == CoverageClass.UNKNOWN_RELEVANCE


@pytest.mark.parametrize(
    "command",
    [
        "arp static 192.0.2.1 0011-2233-4455",
        "ip address 192.0.2.1 255.255.255.0",
        "aaa authentication-scheme default",
        "stp enable",
        "http redirect enable",
        "port default vlan 70",
    ],
)
def test_huawei_registry_does_not_match_broad_command_prefixes(command):
    assert HuaweiVRPCoverageRegistry().match_unsupported_family(command) is None


@pytest.mark.parametrize("command", ["quit", "return"])
def test_huawei_registry_has_narrow_structural_allowlist(command):
    assert HuaweiVRPCoverageRegistry().is_out_of_scope(command)


def test_unknown_structural_looking_command_is_not_out_of_scope():
    assert not HuaweiVRPCoverageRegistry().is_out_of_scope("system-view")
