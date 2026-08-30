from src.domain.models import (
    ConfigState,
    InterfaceConfig,
    InterfaceMode,
    ParsedConfig,
    SourceLine,
    VtyConfig,
)


class CiscoIOSParser:
    def parse(self, raw_text: str) -> ParsedConfig:
        config = ParsedConfig(vendor="cisco_ios")

        current_interface: InterfaceConfig | None = None
        current_vty: VtyConfig | None = None

        for line_number, raw_line in enumerate(
            raw_text.splitlines(),
            start=1,
        ):
            stripped = raw_line.strip()

            if not stripped:
                continue

            source_line = SourceLine(
                line_number=line_number,
                text=raw_line.rstrip(),
            )

            # Cisco config'lerinde ! genellikle blok ayırıcıdır.
            if stripped == "!":
                current_interface = None
                current_vty = None
                continue

            # Bir interface bloğunun altındaki girintili satırlar.
            if current_interface is not None and raw_line[:1].isspace():
                current_interface.raw_lines.append(source_line)

                if stripped.startswith("description "):
                    current_interface.description = stripped.removeprefix(
                        "description "
                    ).strip()

                elif stripped == "switchport mode access":
                    current_interface.mode = InterfaceMode.ACCESS

                elif stripped == "switchport mode trunk":
                    current_interface.mode = InterfaceMode.TRUNK

                elif stripped.startswith("switchport access vlan "):
                    vlan_text = stripped.removeprefix(
                        "switchport access vlan "
                    ).strip()

                    try:
                        current_interface.access_vlan = int(vlan_text)
                    except ValueError:
                        config.unparsed_lines.append(source_line)

                elif stripped == "ip dhcp snooping trust":
                    current_interface.dhcp_snooping_trust = (
                        ConfigState.ENABLED
                    )

                elif stripped == "no ip dhcp snooping trust":
                    current_interface.dhcp_snooping_trust = (
                        ConfigState.DISABLED
                    )

                elif stripped == "switchport port-security":
                    current_interface.port_security = ConfigState.ENABLED

                elif stripped == "no switchport port-security":
                    current_interface.port_security = ConfigState.DISABLED

                elif stripped in (
                    "spanning-tree portfast",
                    "spanning-tree portfast edge",
                ):
                    current_interface.portfast = ConfigState.ENABLED

                elif stripped == "spanning-tree bpduguard enable":
                    current_interface.bpdu_guard = ConfigState.ENABLED

                elif stripped == "spanning-tree bpduguard disable":
                    current_interface.bpdu_guard = ConfigState.DISABLED

                elif stripped == "no spanning-tree bpduguard":
                    current_interface.bpdu_guard = (
                        ConfigState.NOT_CONFIGURED
                    )

                elif stripped == "ip verify source":
                    current_interface.ip_source_guard = ConfigState.ENABLED

                elif stripped == "no ip verify source":
                    current_interface.ip_source_guard = ConfigState.DISABLED

                else:
                    config.unparsed_lines.append(source_line)

                continue

            if current_vty is not None and raw_line[:1].isspace():
                current_vty.raw_lines.append(source_line)

                if stripped.startswith("transport input "):
                    self._parse_transport_input(
                        stripped,
                        source_line,
                        current_vty,
                        config,
                    )
                else:
                    config.unparsed_lines.append(source_line)

                continue

            # Girintisiz yeni bir komut geldiyse interface bloğu bitmiştir.
            current_interface = None
            current_vty = None

            if stripped.startswith("interface "):
                interface_name = stripped.removeprefix(
                    "interface "
                ).strip()

                current_interface = InterfaceConfig(
                    name=interface_name,
                    raw_lines=[source_line],
                )

                config.interfaces.append(current_interface)

            elif stripped.startswith("line vty "):
                range_tokens = stripped.split()

                if len(range_tokens) != 4:
                    config.unparsed_lines.append(source_line)
                    continue

                try:
                    start = int(range_tokens[2])
                    end = int(range_tokens[3])
                except ValueError:
                    config.unparsed_lines.append(source_line)
                    continue

                current_vty = VtyConfig(
                    start=start,
                    end=end,
                    raw_lines=[source_line],
                )
                config.vty_lines.append(current_vty)

            elif stripped.startswith("hostname "):
                config.hostname = stripped.removeprefix(
                    "hostname "
                ).strip()

            elif stripped == "ip dhcp snooping":
                config.dhcp_snooping_global = ConfigState.ENABLED
                config.dhcp_snooping_global_evidence = source_line

            elif stripped == "no ip dhcp snooping":
                config.dhcp_snooping_global = ConfigState.DISABLED
                config.dhcp_snooping_global_evidence = source_line

            elif stripped == "ip http server":
                config.http_server = ConfigState.ENABLED
                config.http_server_evidence = source_line

            elif stripped == "no ip http server":
                config.http_server = ConfigState.DISABLED
                config.http_server_evidence = source_line

            elif stripped == "ip http secure-server":
                config.https_server = ConfigState.ENABLED
                config.https_server_evidence = source_line

            elif stripped == "no ip http secure-server":
                config.https_server = ConfigState.DISABLED
                config.https_server_evidence = source_line

            elif stripped.startswith("ip dhcp snooping vlan "):
                vlan_text = stripped.removeprefix(
                    "ip dhcp snooping vlan "
                ).strip()

                try:
                    vlan_id = int(vlan_text)
                    
                    config.dhcp_snooping_vlans.add(vlan_id)
                    config.dhcp_snooping_vlan_evidence[vlan_id] = source_line
                except ValueError:
                    config.unparsed_lines.append(source_line)

            elif stripped.startswith("ip arp inspection vlan "):
                vlan_text = stripped.removeprefix(
                    "ip arp inspection vlan "
                ).strip()

                try:
                    vlan_id = int(vlan_text)

                    config.dai_vlans.add(vlan_id)
                    config.dai_vlan_evidence[vlan_id] = source_line
                except ValueError:
                    config.unparsed_lines.append(source_line)

            elif stripped in (
                "spanning-tree portfast default",
                "spanning-tree portfast edge default",
            ):
                config.portfast_default = ConfigState.ENABLED
                config.portfast_default_evidence = source_line

            elif stripped in (
                "no spanning-tree portfast default",
                "no spanning-tree portfast edge default",
            ):
                config.portfast_default = ConfigState.DISABLED
                config.portfast_default_evidence = source_line

            elif stripped in (
                "spanning-tree portfast bpduguard default",
                "spanning-tree portfast edge bpduguard default",
            ):
                config.bpdu_guard_default = ConfigState.ENABLED
                config.bpdu_guard_default_evidence = source_line

            elif stripped in (
                "no spanning-tree portfast bpduguard default",
                "no spanning-tree portfast edge bpduguard default",
            ):
                config.bpdu_guard_default = ConfigState.DISABLED
                config.bpdu_guard_default_evidence = source_line

            else:
                config.unparsed_lines.append(source_line)

        return config

    @staticmethod
    def _parse_transport_input(
        stripped: str,
        source_line: SourceLine,
        vty: VtyConfig,
        config: ParsedConfig,
    ) -> None:
        if vty.transport_input_evidence is not None:
            vty.transport_input.clear()
            vty.transport_input_evidence = None
            vty.transport_input_state = ConfigState.UNKNOWN
            config.unparsed_lines.append(source_line)
            return

        if vty.transport_input_state == ConfigState.UNKNOWN:
            config.unparsed_lines.append(source_line)
            return

        tokens = stripped.removeprefix("transport input ").split()
        token_set = set(tokens)

        if token_set == {"all"}:
            vty.transport_input = {"ssh", "telnet"}
            vty.transport_input_state = ConfigState.ENABLED
        elif token_set == {"none"}:
            vty.transport_input = set()
            vty.transport_input_state = ConfigState.DISABLED
        elif tokens and token_set <= {"ssh", "telnet"}:
            vty.transport_input = token_set
            vty.transport_input_state = ConfigState.ENABLED
        else:
            vty.transport_input.clear()
            vty.transport_input_state = ConfigState.UNKNOWN
            config.unparsed_lines.append(source_line)
            return

        vty.transport_input_evidence = source_line
