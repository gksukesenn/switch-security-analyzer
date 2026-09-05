from dataclasses import dataclass
from typing import Protocol

from src.coverage.aruba_aos_s_registry import ArubaAOSSCoverageRegistry
from src.coverage.aruba_registry import ArubaCoverageRegistry
from src.coverage.cisco_registry import CiscoCoverageRegistry
from src.coverage.huawei_vrp_registry import HuaweiVRPCoverageRegistry
from src.coverage.registry import CoverageRegistry
from src.domain.models import ParsedConfig
from src.domain.vendors import UnsupportedVendorError, Vendor
from src.parsers.cisco.ios import CiscoIOSParser
from src.parsers.huawei.vrp import HuaweiVRPParser
from src.parsers.aruba.aos_s import ArubaAOSSParser
from src.parsers.aruba.aos_cx import ArubaAOSCXParser
from src.renderers.safe_config import (
    ArubaAOSSafeConfigRenderer,
    ArubaSafeConfigRenderer,
    CiscoSafeConfigRenderer,
    HuaweiVRPSafeConfigRenderer,
    SafeConfigRenderer,
)


CISCO_SUPPORTED_RULE_IDS = frozenset({
    "DISCOVERY-001",
    "DHCP-001",
    "DHCP-002",
    "DHCP-003",
    "DAI-001",
    "IPSG-001",
    "PORTSEC-001",
    "STP-001",
    "MGMT-001",
    "MGMT-002",
})

ARUBA_AOS_CX_SUPPORTED_RULE_IDS = frozenset({
    "DHCP-001",
    "DHCP-002",
    "DHCP-003",
    "DAI-001",
    "STP-001",
})

ARUBA_AOS_S_SUPPORTED_RULE_IDS = frozenset({
    "DHCP-001",
    "DHCP-002",
    "DHCP-003",
    "DAI-001",
})

HUAWEI_VRP_SUPPORTED_RULE_IDS = frozenset({
    "DHCP-001",
    "DHCP-002",
    "DHCP-003",
    "STP-001",
})


class ConfigParser(Protocol):
    def parse(self, raw_text: str) -> ParsedConfig: ...


@dataclass(frozen=True)
class VendorComponents:
    parser: ConfigParser
    renderer: SafeConfigRenderer
    coverage_registry: CoverageRegistry
    supported_rule_ids: frozenset[str]


class VendorComponentSelector:
    def parser_for(self, vendor: Vendor) -> ConfigParser:
        if vendor == Vendor.CISCO_IOS:
            return CiscoIOSParser()
        if vendor == Vendor.ARUBA_AOS_CX:
            return ArubaAOSCXParser()
        if vendor == Vendor.ARUBA_AOS_S:
            return ArubaAOSSParser()
        if vendor == Vendor.HUAWEI_VRP:
            return HuaweiVRPParser()
        raise UnsupportedVendorError(vendor)

    def renderer_for(self, vendor: Vendor) -> SafeConfigRenderer:
        if vendor == Vendor.CISCO_IOS:
            return CiscoSafeConfigRenderer()
        if vendor == Vendor.ARUBA_AOS_CX:
            return ArubaSafeConfigRenderer()
        if vendor == Vendor.ARUBA_AOS_S:
            return ArubaAOSSafeConfigRenderer()
        if vendor == Vendor.HUAWEI_VRP:
            return HuaweiVRPSafeConfigRenderer()
        raise UnsupportedVendorError(vendor)

    def coverage_registry_for(self, vendor: Vendor) -> CoverageRegistry:
        if vendor == Vendor.CISCO_IOS:
            return CiscoCoverageRegistry()
        if vendor == Vendor.ARUBA_AOS_CX:
            return ArubaCoverageRegistry()
        if vendor == Vendor.ARUBA_AOS_S:
            return ArubaAOSSCoverageRegistry()
        if vendor == Vendor.HUAWEI_VRP:
            return HuaweiVRPCoverageRegistry()
        raise UnsupportedVendorError(vendor)

    def components_for(self, vendor: Vendor) -> VendorComponents:
        return VendorComponents(
            parser=self.parser_for(vendor),
            renderer=self.renderer_for(vendor),
            coverage_registry=self.coverage_registry_for(vendor),
            supported_rule_ids=self.supported_rule_ids_for(vendor),
        )

    @staticmethod
    def supported_rule_ids_for(vendor: Vendor) -> frozenset[str]:
        if vendor == Vendor.CISCO_IOS:
            return CISCO_SUPPORTED_RULE_IDS
        if vendor == Vendor.ARUBA_AOS_CX:
            return ARUBA_AOS_CX_SUPPORTED_RULE_IDS
        if vendor == Vendor.ARUBA_AOS_S:
            return ARUBA_AOS_S_SUPPORTED_RULE_IDS
        if vendor == Vendor.HUAWEI_VRP:
            return HUAWEI_VRP_SUPPORTED_RULE_IDS
        raise UnsupportedVendorError(vendor)
