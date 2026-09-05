import pytest

from src.renderers.safe_config import (
    CiscoSafeConfigRenderer,
    UnavailableSafeConfigRenderer,
)
from src.services.analyzer import AnalyzerService


def test_cisco_renders_sorted_dhcp_snooping_vlan_scope():
    renderer = CiscoSafeConfigRenderer()

    assert renderer.enable_dhcp_snooping({30, 10, 20}) == (
        "ip dhcp snooping\n"
        "ip dhcp snooping vlan 10\n"
        "ip dhcp snooping vlan 20\n"
        "ip dhcp snooping vlan 30"
    )


def test_cisco_renders_dhcp_snooping_placeholder_for_empty_scope():
    assert CiscoSafeConfigRenderer().enable_dhcp_snooping([]) == (
        "ip dhcp snooping\n"
        "ip dhcp snooping vlan <intended-vlan-id>"
    )


def test_cisco_renders_dhcp_snooping_vlan_addition():
    assert CiscoSafeConfigRenderer().add_dhcp_snooping_vlan(20) == (
        "ip dhcp snooping\nip dhcp snooping vlan 20"
    )


def test_cisco_removes_trust_while_preserving_access_mode_and_vlan():
    assert CiscoSafeConfigRenderer().correct_trusted_access_interface(
        "GigabitEthernet1/0/5", 20
    ) == (
        "interface GigabitEthernet1/0/5\n"
        " switchport mode access\n"
        " switchport access vlan 20\n"
        " no ip dhcp snooping trust"
    )


def test_cisco_renders_dai_vlan():
    assert CiscoSafeConfigRenderer().enable_dai_vlan(20) == (
        "ip arp inspection vlan 20"
    )


@pytest.mark.parametrize(
    ("operation", "command"),
    [
        ("enable_bpdu_guard", "spanning-tree bpduguard enable"),
        ("enable_port_security", "switchport port-security"),
        ("enable_ip_source_guard", "ip verify source"),
    ],
)
def test_cisco_renders_naturally_sorted_interface_blocks(
    operation,
    command,
):
    renderer = CiscoSafeConfigRenderer()

    result = getattr(renderer, operation)([
        "GigabitEthernet1/0/10",
        "GigabitEthernet1/0/2",
    ])

    assert result == (
        f"interface GigabitEthernet1/0/2\n {command}\n!\n"
        f"interface GigabitEthernet1/0/10\n {command}"
    )


def test_cisco_renders_sorted_vty_ranges_with_separator():
    assert CiscoSafeConfigRenderer().restrict_vty_to_ssh(
        [(5, 15), (0, 4)]
    ) == (
        "line vty 0 4\n transport input ssh\n!\n"
        "line vty 5 15\n transport input ssh"
    )


def test_cisco_renders_parameter_free_http_disable():
    assert CiscoSafeConfigRenderer().disable_insecure_http_server() == (
        "no ip http server"
    )


@pytest.mark.parametrize(
    "render",
    [
        lambda renderer: renderer.enable_dhcp_snooping([20]),
        lambda renderer: renderer.add_dhcp_snooping_vlan(20),
        lambda renderer: renderer.correct_trusted_access_interface(
            "GigabitEthernet1/0/5", 20
        ),
        lambda renderer: renderer.enable_dai_vlan(20),
        lambda renderer: renderer.enable_bpdu_guard(["Gi1/0/1"]),
        lambda renderer: renderer.enable_port_security(["Gi1/0/1"]),
        lambda renderer: renderer.enable_ip_source_guard(["Gi1/0/1"]),
        lambda renderer: renderer.restrict_vty_to_ssh([(0, 4)]),
        lambda renderer: renderer.disable_insecure_http_server(),
    ],
)
def test_unavailable_renderer_returns_n_a_for_every_operation(render):
    assert render(UnavailableSafeConfigRenderer()) == "N/A"


def test_analyzer_does_not_fall_back_when_renderer_is_unavailable():
    analyzer = AnalyzerService(UnavailableSafeConfigRenderer())

    findings = analyzer.analyze("ip http server")

    assert len(findings) == 1
    assert findings[0].rule_id == "MGMT-002"
    assert findings[0].safe_config_example == "N/A"
