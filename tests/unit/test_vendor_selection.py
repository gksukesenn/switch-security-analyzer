from src.coverage.aruba_registry import ArubaCoverageRegistry
from src.coverage.cisco_registry import CiscoCoverageRegistry
from src.domain.vendors import Vendor
from src.parsers.aruba.aos_cx import ArubaAOSCXParser
from src.parsers.cisco.ios import CiscoIOSParser
from src.renderers.safe_config import (
    ArubaSafeConfigRenderer,
    CiscoSafeConfigRenderer,
)
from src.services.coverage import CoverageService
from src.services.vendor_selection import VendorComponentSelector


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
