from src.domain.models import (
    ConfigState,
    InterfaceConfig,
    InterfaceMode,
    ParsedConfig,
    SourceLine,
)


class CiscoIOSParser:
    def parse(self, raw_text: str) -> ParsedConfig:
        config = ParsedConfig(vendor="cisco_ios")

        current_interface: InterfaceConfig | None = None

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

                else:
                    config.unparsed_lines.append(source_line)

                continue

            # Girintisiz yeni bir komut geldiyse interface bloğu bitmiştir.
            current_interface = None

            if stripped.startswith("interface "):
                interface_name = stripped.removeprefix(
                    "interface "
                ).strip()

                current_interface = InterfaceConfig(
                    name=interface_name,
                    raw_lines=[source_line],
                )

                config.interfaces.append(current_interface)

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

            else:
                config.unparsed_lines.append(source_line)

        return config
