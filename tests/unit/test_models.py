from src.domain.models import (
    ConfigState,
    InterfaceConfig,
    InterfaceMode,
    ParsedConfig,
    VtyConfig,
)


def test_interface_defaults_to_not_configured_dhcp_trust():
    interface = InterfaceConfig(
        name="GigabitEthernet1/0/5",
    )

    assert interface.dhcp_snooping_trust == ConfigState.NOT_CONFIGURED
    assert interface.port_security == ConfigState.NOT_CONFIGURED
    assert interface.portfast == ConfigState.NOT_CONFIGURED
    assert interface.bpdu_guard == ConfigState.NOT_CONFIGURED
    assert interface.ip_source_guard == ConfigState.NOT_CONFIGURED
    assert interface.declaration_evidence is None
    assert interface.mode_evidence is None
    assert interface.access_vlan_evidence is None
    assert interface.dhcp_snooping_trust_evidence is None
    assert interface.port_security_evidence is None
    assert interface.portfast_evidence is None
    assert interface.bpdu_guard_evidence is None
    assert interface.ip_source_guard_evidence is None


def test_parsed_config_can_store_dhcp_information():
    interface = InterfaceConfig(
        name="GigabitEthernet1/0/5",
        mode=InterfaceMode.ACCESS,
        access_vlan=10,
        dhcp_snooping_trust=ConfigState.ENABLED,
    )

    config = ParsedConfig(
        vendor="cisco_ios",
        hostname="ACCESS-SW-01",
        dhcp_snooping_global=ConfigState.ENABLED,
        dhcp_snooping_vlans={10},
        interfaces=[interface],
    )

    assert config.vendor == "cisco_ios"
    assert config.hostname == "ACCESS-SW-01"
    assert config.dhcp_snooping_global == ConfigState.ENABLED
    assert config.dhcp_snooping_vlans == {10}
    assert config.dai_vlans == set()
    assert config.dai_vlan_evidence == {}

    assert len(config.interfaces) == 1
    assert config.interfaces[0].mode == InterfaceMode.ACCESS
    assert config.interfaces[0].access_vlan == 10
    assert (
        config.interfaces[0].dhcp_snooping_trust
        == ConfigState.ENABLED
    )


def test_management_server_states_default_to_not_configured():
    config = ParsedConfig(vendor="cisco_ios")

    assert config.http_server == ConfigState.NOT_CONFIGURED
    assert config.https_server == ConfigState.NOT_CONFIGURED
    assert config.http_server_evidence is None
    assert config.https_server_evidence is None


def test_vty_defaults_to_transport_not_configured():
    vty = VtyConfig(start=0, end=4)

    assert vty.transport_input == set()
    assert vty.transport_input_evidence is None
    assert vty.transport_input_state == ConfigState.NOT_CONFIGURED
