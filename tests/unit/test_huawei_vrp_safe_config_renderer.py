import pytest

from src.renderers.safe_config import HuaweiVRPSafeConfigRenderer


def test_huawei_renders_dhcp_first_slice_operations():
    renderer = HuaweiVRPSafeConfigRenderer()

    assert renderer.enable_dhcp_snooping([20, 10]) == (
        "dhcp snooping enable\n"
        "vlan 10\n dhcp snooping enable\nquit\n"
        "vlan 20\n dhcp snooping enable\nquit"
    )
    assert renderer.add_dhcp_snooping_vlan(20) == (
        "dhcp snooping enable\n"
        "vlan 20\n dhcp snooping enable\nquit"
    )


def test_huawei_sorts_and_deduplicates_dhcp_vlan_scope():
    assert HuaweiVRPSafeConfigRenderer().enable_dhcp_snooping(
        [777, 10, 20, 10]
    ) == (
        "dhcp snooping enable\n"
        "vlan 10\n dhcp snooping enable\nquit\n"
        "vlan 20\n dhcp snooping enable\nquit\n"
        "vlan 777\n dhcp snooping enable\nquit"
    )


def test_huawei_empty_dhcp_scope_uses_placeholder():
    assert HuaweiVRPSafeConfigRenderer().enable_dhcp_snooping([]) == (
        "dhcp snooping enable\n"
        "vlan <intended-vlan-id>\n dhcp snooping enable\nquit"
    )


def test_huawei_removes_endpoint_trust_without_changing_vlan_or_mode():
    assert HuaweiVRPSafeConfigRenderer().correct_trusted_access_interface(
        "GigabitEthernet0/0/1",
        70,
    ) == (
        "interface GigabitEthernet0/0/1\n"
        " undo dhcp snooping trusted\n"
        "quit"
    )


@pytest.mark.parametrize("interfaces", [[], ["GigabitEthernet0/0/1"]])
def test_huawei_bpdu_protection_is_one_global_command(interfaces):
    assert HuaweiVRPSafeConfigRenderer().enable_bpdu_guard(interfaces) == (
        "stp bpdu-protection"
    )


@pytest.mark.parametrize(
    "render",
    [
        lambda renderer: renderer.enable_dai_vlan(20),
        lambda renderer: renderer.enable_port_security(["GE0/0/1"]),
        lambda renderer: renderer.enable_ip_source_guard(["GE0/0/1"]),
        lambda renderer: renderer.restrict_vty_to_ssh([(0, 4)]),
        lambda renderer: renderer.disable_insecure_http_server(),
    ],
)
def test_huawei_returns_n_a_for_deferred_operations(render):
    assert render(HuaweiVRPSafeConfigRenderer()) == "N/A"
