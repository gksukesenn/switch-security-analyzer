from dataclasses import dataclass
from typing import Protocol

from src.coverage.aruba_aos_s_registry import ArubaAOSSCoverageRegistry
from src.coverage.aruba_registry import ArubaCoverageRegistry
from src.coverage.cisco_registry import CiscoCoverageRegistry
from src.coverage.registry import CoverageRegistry
from src.domain.models import ParsedConfig
from src.domain.vendors import UnsupportedVendorError, Vendor
from src.parsers.cisco.ios import CiscoIOSParser
from src.parsers.aruba.aos_s import ArubaAOSSParser
from src.parsers.aruba.aos_cx import ArubaAOSCXParser
from src.renderers.safe_config import (
    ArubaAOSSafeConfigRenderer,
    ArubaSafeConfigRenderer,
    CiscoSafeConfigRenderer,
    SafeConfigRenderer,
)


class ConfigParser(Protocol):
    def parse(self, raw_text: str) -> ParsedConfig: ...


@dataclass(frozen=True)
class VendorComponents:
    parser: ConfigParser
    renderer: SafeConfigRenderer
    coverage_registry: CoverageRegistry


class VendorComponentSelector:
    def parser_for(self, vendor: Vendor) -> ConfigParser:
        if vendor == Vendor.CISCO_IOS:
            return CiscoIOSParser()
        if vendor == Vendor.ARUBA_AOS_CX:
            return ArubaAOSCXParser()
        if vendor == Vendor.ARUBA_AOS_S:
            return ArubaAOSSParser()
        raise UnsupportedVendorError(vendor)

    def renderer_for(self, vendor: Vendor) -> SafeConfigRenderer:
        if vendor == Vendor.CISCO_IOS:
            return CiscoSafeConfigRenderer()
        if vendor == Vendor.ARUBA_AOS_CX:
            return ArubaSafeConfigRenderer()
        if vendor == Vendor.ARUBA_AOS_S:
            return ArubaAOSSafeConfigRenderer()
        raise UnsupportedVendorError(vendor)

    def coverage_registry_for(self, vendor: Vendor) -> CoverageRegistry:
        if vendor == Vendor.CISCO_IOS:
            return CiscoCoverageRegistry()
        if vendor == Vendor.ARUBA_AOS_CX:
            return ArubaCoverageRegistry()
        if vendor == Vendor.ARUBA_AOS_S:
            return ArubaAOSSCoverageRegistry()
        raise UnsupportedVendorError(vendor)

    def components_for(self, vendor: Vendor) -> VendorComponents:
        return VendorComponents(
            parser=self.parser_for(vendor),
            renderer=self.renderer_for(vendor),
            coverage_registry=self.coverage_registry_for(vendor),
        )
