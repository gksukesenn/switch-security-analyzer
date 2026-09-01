import pytest

from src.renderers.safe_config import ArubaSafeConfigRenderer


def test_aruba_renders_supported_first_slice_operations():
    renderer = ArubaSafeConfigRenderer()

    assert renderer.enable_dhcp_snooping([30, 20]) == (
        "dhcpv4-snooping\n"
        "vlan 20\n dhcpv4-snooping\n"
        "vlan 30\n dhcpv4-snooping"
    )
    assert renderer.add_dhcp_snooping_vlan(20) == (
        "dhcpv4-snooping\nvlan 20\n dhcpv4-snooping"
    )
    assert renderer.correct_trusted_access_interface("1/1/1", 20) == (
        "interface 1/1/1\n no dhcpv4-snooping trust"
    )
    assert renderer.enable_dai_vlan(20) == "vlan 20\n arp inspection"
    assert renderer.enable_bpdu_guard(["1/1/10", "1/1/2"]) == (
        "interface 1/1/2\n spanning-tree bpdu-guard\n!\n"
        "interface 1/1/10\n spanning-tree bpdu-guard"
    )


def test_aruba_renders_empty_dhcp_scope_placeholder():
    assert ArubaSafeConfigRenderer().enable_dhcp_snooping([]) == (
        "dhcpv4-snooping\n"
        "vlan <intended-vlan-id>\n dhcpv4-snooping"
    )


@pytest.mark.parametrize(
    "render",
    [
        lambda renderer: renderer.enable_port_security(["1/1/1"]),
        lambda renderer: renderer.enable_ip_source_guard(["1/1/1"]),
        lambda renderer: renderer.restrict_vty_to_ssh([(0, 4)]),
        lambda renderer: renderer.disable_insecure_http_server(),
    ],
)
def test_aruba_returns_n_a_for_unsupported_operations(render):
    assert render(ArubaSafeConfigRenderer()) == "N/A"
