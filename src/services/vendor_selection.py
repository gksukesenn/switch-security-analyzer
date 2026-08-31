from dataclasses import dataclass
from typing import Protocol

from src.coverage.cisco_registry import CiscoCoverageRegistry
from src.coverage.registry import CoverageRegistry
from src.domain.models import ParsedConfig
from src.domain.vendors import UnsupportedVendorError, Vendor
from src.parsers.cisco.ios import CiscoIOSParser
from src.renderers.safe_config import (
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
        raise UnsupportedVendorError(vendor)

    def renderer_for(self, vendor: Vendor) -> SafeConfigRenderer:
        if vendor == Vendor.CISCO_IOS:
            return CiscoSafeConfigRenderer()
        raise UnsupportedVendorError(vendor)

    def coverage_registry_for(self, vendor: Vendor) -> CoverageRegistry:
        if vendor == Vendor.CISCO_IOS:
            return CiscoCoverageRegistry()
        raise UnsupportedVendorError(vendor)

    def components_for(self, vendor: Vendor) -> VendorComponents:
        return VendorComponents(
            parser=self.parser_for(vendor),
            renderer=self.renderer_for(vendor),
            coverage_registry=self.coverage_registry_for(vendor),
        )
