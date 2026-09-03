import pytest

from src.renderers.safe_config import ArubaAOSSafeConfigRenderer


def test_aos_s_renders_supported_first_slice_operations():
    renderer = ArubaAOSSafeConfigRenderer()

    assert renderer.enable_dhcp_snooping([777, 10, 601]) == (
        "dhcp-snooping\ndhcp-snooping vlan 10 601 777"
    )
    assert renderer.add_dhcp_snooping_vlan(20) == "dhcp-snooping vlan 20"
    assert renderer.correct_trusted_access_interface("1", 20) == (
        "interface 1\n no dhcp-snooping trust\n exit"
    )
    assert renderer.enable_dai_vlan(20) == "arp-protect vlan 20"


def test_aos_s_orders_and_deduplicates_dhcp_vlan_scope():
    assert ArubaAOSSafeConfigRenderer().enable_dhcp_snooping(
        [777, 10, 620, 601, 10]
    ) == "dhcp-snooping\ndhcp-snooping vlan 10 601 620 777"


@pytest.mark.parametrize(
    "render",
    [
        lambda renderer: renderer.enable_bpdu_guard(["1"]),
        lambda renderer: renderer.enable_port_security(["1"]),
        lambda renderer: renderer.enable_ip_source_guard(["1"]),
        lambda renderer: renderer.restrict_vty_to_ssh([(0, 4)]),
        lambda renderer: renderer.disable_insecure_http_server(),
    ],
)
def test_aos_s_returns_n_a_for_every_unsupported_operation(render):
    assert render(ArubaAOSSafeConfigRenderer()) == "N/A"
