import pytest

from src.coverage.aruba_aos_s_registry import ArubaAOSSCoverageRegistry
from src.coverage.aruba_registry import ArubaCoverageRegistry
from src.coverage.cisco_registry import CiscoCoverageRegistry
from src.coverage.huawei_vrp_registry import HuaweiVRPCoverageRegistry
from src.domain.vendors import Vendor
from src.parsers.aruba.aos_s import ArubaAOSSParser
from src.parsers.aruba.aos_cx import ArubaAOSCXParser
from src.parsers.cisco.ios import CiscoIOSParser
from src.parsers.huawei.vrp import HuaweiVRPParser
from src.renderers.safe_config import (
    ArubaAOSSafeConfigRenderer,
    ArubaSafeConfigRenderer,
    CiscoSafeConfigRenderer,
    HuaweiVRPSafeConfigRenderer,
)
from src.services.analysis import AnalysisApplicationService
from src.services.analyzer import AnalyzerService
from src.services.coverage import CoverageService
from src.services.vendor_selection import (
    ARUBA_AOS_CX_SUPPORTED_RULE_IDS,
    ARUBA_AOS_S_SUPPORTED_RULE_IDS,
    CISCO_SUPPORTED_RULE_IDS,
    HUAWEI_VRP_SUPPORTED_RULE_IDS,
    VendorComponentSelector,
)


REGISTERED_RULE_IDS = frozenset(
    rule.rule_id for rule in AnalyzerService().rules
)


def test_selector_returns_cisco_parser():
    parser = VendorComponentSelector().parser_for(Vendor.CISCO_IOS)

    assert isinstance(parser, CiscoIOSParser)


def test_selector_returns_cisco_renderer():
    renderer = VendorComponentSelector().renderer_for(Vendor.CISCO_IOS)

    assert isinstance(renderer, CiscoSafeConfigRenderer)


def test_selector_routes_cisco_to_cisco_coverage_registry():
    registry = VendorComponentSelector().coverage_registry_for(
        Vendor.CISCO_IOS
    )

    assert isinstance(registry, CiscoCoverageRegistry)
    assert registry.match_unsupported_family("aaa new-model") is not None


def test_coverage_service_uses_injected_registry():
    class OutOfScopeRegistry:
        commands: list[str] = []

        def match_unsupported_family(self, command):
            self.commands.append(command)
            return None

        def is_out_of_scope(self, command):
            self.commands.append(command)
            return True

    registry = OutOfScopeRegistry()

    report = CoverageService(registry=registry).evaluate("unknown command")

    assert report.out_of_scope == 1
    assert registry.commands == ["unknown command", "unknown command"]


def test_aruba_components_are_selected_together_without_cisco_fallback():
    components = VendorComponentSelector().components_for(
        Vendor.ARUBA_AOS_CX
    )

    assert isinstance(components.parser, ArubaAOSCXParser)
    assert isinstance(components.renderer, ArubaSafeConfigRenderer)
    assert isinstance(components.coverage_registry, ArubaCoverageRegistry)
    assert not isinstance(components.parser, CiscoIOSParser)
    assert not isinstance(components.renderer, CiscoSafeConfigRenderer)
    assert not isinstance(
        components.coverage_registry, CiscoCoverageRegistry
    )


def test_aruba_aos_s_components_are_selected_together():
    components = VendorComponentSelector().components_for(
        Vendor.ARUBA_AOS_S
    )

    assert isinstance(components.parser, ArubaAOSSParser)
    assert isinstance(components.renderer, ArubaAOSSafeConfigRenderer)
    assert isinstance(
        components.coverage_registry,
        ArubaAOSSCoverageRegistry,
    )


def test_huawei_vrp_components_are_selected_together_without_fallback():
    components = VendorComponentSelector().components_for(
        Vendor.HUAWEI_VRP
    )

    assert isinstance(components.parser, HuaweiVRPParser)
    assert isinstance(components.renderer, HuaweiVRPSafeConfigRenderer)
    assert isinstance(
        components.coverage_registry,
        HuaweiVRPCoverageRegistry,
    )
    assert not isinstance(components.parser, CiscoIOSParser)
    assert not isinstance(components.renderer, CiscoSafeConfigRenderer)
    assert not isinstance(
        components.coverage_registry,
        CiscoCoverageRegistry,
    )


def test_platform_rule_support_sets_are_explicit_and_registered():
    assert CISCO_SUPPORTED_RULE_IDS == REGISTERED_RULE_IDS
    assert ARUBA_AOS_CX_SUPPORTED_RULE_IDS == {
        "DHCP-001",
        "DHCP-002",
        "DHCP-003",
        "DAI-001",
        "STP-001",
    }
    assert ARUBA_AOS_S_SUPPORTED_RULE_IDS == {
        "DHCP-001",
        "DHCP-002",
        "DHCP-003",
        "DAI-001",
    }
    assert HUAWEI_VRP_SUPPORTED_RULE_IDS == {
        "DHCP-001",
        "DHCP-002",
        "DHCP-003",
        "STP-001",
    }
    for vendor in Vendor:
        components = VendorComponentSelector().components_for(vendor)
        assert components.supported_rule_ids <= REGISTERED_RULE_IDS


@pytest.mark.parametrize(
    ("vendor", "config", "supported_rule_ids", "assessed_rule_count"),
    [
        (
            Vendor.ARUBA_AOS_CX,
            "dhcpv4-snooping\n"
            "vlan 20\n dhcpv4-snooping\n!\n"
            "interface 1/1/1\n"
            " no routing\n vlan access 20\n"
            " spanning-tree port-type admin-edge\n"
            " spanning-tree bpdu-guard\n!\n",
            ARUBA_AOS_CX_SUPPORTED_RULE_IDS,
            5,
        ),
        (
            Vendor.ARUBA_AOS_S,
            "dhcp-snooping\n"
            "dhcp-snooping vlan 20\n"
            "arp-protect vlan 20\n"
            "vlan 20\n untagged 1\n exit\n",
            ARUBA_AOS_S_SUPPORTED_RULE_IDS,
            4,
        ),
    ],
)
def test_aruba_policy_keeps_all_evaluations_and_existing_n_a_posture(
    vendor,
    config,
    supported_rule_ids,
    assessed_rule_count,
):
    result = AnalysisApplicationService().analyze(config, vendor)

    assert set(result.evaluations) == REGISTERED_RULE_IDS
    for rule_id in REGISTERED_RULE_IDS - supported_rule_ids:
        assert result.evaluations[rule_id].findings == []
        assert result.evaluations[rule_id].assessed_units == 0
    assert result.posture.assessed_rule_count == assessed_rule_count
    assert result.posture.total_rule_count == 10
    assert result.posture.score is None
    assert result.posture.risk_level is None


def test_cisco_policy_preserves_all_nine_rule_assessments():
    config = """ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
no ip http server
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 switchport port-security
 spanning-tree portfast
 spanning-tree bpduguard enable
 ip verify source
!
line vty 0 4
 transport input ssh
"""

    result = AnalysisApplicationService().analyze(config, Vendor.CISCO_IOS)

    assert set(result.evaluations) == REGISTERED_RULE_IDS
    assert all(
        evaluation.assessed_units > 0
        for rule_id, evaluation in result.evaluations.items()
        if rule_id != "DISCOVERY-001"
    )
    assert result.evaluations["DISCOVERY-001"].assessed_units == 0
    assert result.findings == ()
    assert result.posture.assessed_rule_count == 9
    assert result.posture.total_rule_count == 10
    assert result.posture.score == 100.0
