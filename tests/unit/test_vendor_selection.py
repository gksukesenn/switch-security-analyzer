import pytest

from src.coverage.cisco_registry import CiscoCoverageRegistry
from src.domain.vendors import UnsupportedVendorError, Vendor
from src.parsers.cisco.ios import CiscoIOSParser
from src.renderers.safe_config import CiscoSafeConfigRenderer
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


@pytest.mark.parametrize(
    "selection",
    [
        lambda selector: selector.parser_for(Vendor.ARUBA_AOS_CX),
        lambda selector: selector.renderer_for(Vendor.ARUBA_AOS_CX),
        lambda selector: selector.coverage_registry_for(
            Vendor.ARUBA_AOS_CX
        ),
        lambda selector: selector.components_for(Vendor.ARUBA_AOS_CX),
    ],
)
def test_unsupported_vendor_never_falls_back_to_cisco(selection):
    with pytest.raises(
        UnsupportedVendorError,
        match="vendor is not supported: aruba_aos_cx",
    ):
        selection(VendorComponentSelector())
