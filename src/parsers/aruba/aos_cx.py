from src.domain.models import (
    ConfigState,
    CoverageClass,
    InterfaceConfig,
    InterfaceMode,
    ParsedConfig,
    SourceLine,
)
from src.domain.vendors import Vendor


class ArubaAOSCXParser:
    def parse(self, raw_text: str) -> ParsedConfig:
        config = ParsedConfig(vendor=Vendor.ARUBA_AOS_CX.value)
        current_interface: InterfaceConfig | None = None
        current_vlan: int | None = None

        for line_number, raw_line in enumerate(raw_text.splitlines(), 1):
            stripped = raw_line.strip()
            if not stripped:
                continue

            source_line = SourceLine(line_number, raw_line.rstrip())
            if stripped == "!":
                current_interface = None
                current_vlan = None
                continue

            if raw_line[:1].isspace() and current_interface is not None:
                current_interface.raw_lines.append(source_line)
                self._parse_interface_line(
                    stripped,
                    source_line,
                    current_interface,
                    config,
                )
                continue

            if raw_line[:1].isspace() and current_vlan is not None:
                self._parse_vlan_line(
                    stripped,
                    source_line,
                    current_vlan,
                    config,
                )
                continue

            current_interface = None
            current_vlan = None

            if stripped.startswith("interface "):
                name = stripped.removeprefix("interface ").strip()
                current_interface = InterfaceConfig(
                    name=name,
                    declaration_evidence=source_line,
                    port_security=ConfigState.UNKNOWN,
                    ip_source_guard=ConfigState.UNKNOWN,
                    raw_lines=[source_line],
                )
                config.interfaces.append(current_interface)
                self._record_supported(config, source_line)
            elif stripped.startswith("vlan "):
                vlan_text = stripped.removeprefix("vlan ").strip()
                try:
                    current_vlan = int(vlan_text)
                    self._record_supported(config, source_line)
                except ValueError:
                    config.unparsed_lines.append(source_line)
            elif stripped.startswith("hostname "):
                config.hostname = stripped.removeprefix("hostname ").strip()
                self._record_coverage(
                    config, source_line, CoverageClass.OUT_OF_SCOPE
                )
            elif stripped == "dhcpv4-snooping":
                config.dhcp_snooping_global = ConfigState.ENABLED
                config.dhcp_snooping_global_evidence = source_line
                self._record_supported(config, source_line)
            elif stripped == "no dhcpv4-snooping":
                config.dhcp_snooping_global = ConfigState.DISABLED
                config.dhcp_snooping_global_evidence = source_line
                self._record_supported(config, source_line)
            else:
                config.unparsed_lines.append(source_line)

        return config

    @staticmethod
    def _parse_interface_line(
        stripped: str,
        source_line: SourceLine,
        interface: InterfaceConfig,
        config: ParsedConfig,
    ) -> None:
        if stripped == "no routing":
            interface.mode = InterfaceMode.ACCESS
            interface.mode_evidence = source_line
            interface.access_vlan = 1
            interface.access_vlan_evidence = source_line
        elif stripped.startswith("vlan access "):
            vlan_text = stripped.removeprefix("vlan access ").strip()
            try:
                interface.access_vlan = int(vlan_text)
            except ValueError:
                config.unparsed_lines.append(source_line)
                return
            interface.mode = InterfaceMode.ACCESS
            interface.mode_evidence = source_line
            interface.access_vlan_evidence = source_line
        elif stripped == "dhcpv4-snooping trust":
            interface.dhcp_snooping_trust = ConfigState.ENABLED
            interface.dhcp_snooping_trust_evidence = source_line
        elif stripped == "no dhcpv4-snooping trust":
            interface.dhcp_snooping_trust = ConfigState.DISABLED
            interface.dhcp_snooping_trust_evidence = source_line
        elif stripped == "spanning-tree port-type admin-edge":
            interface.portfast = ConfigState.ENABLED
            interface.portfast_evidence = source_line
        elif stripped == "no spanning-tree port-type admin-edge":
            interface.portfast = ConfigState.DISABLED
            interface.portfast_evidence = source_line
        elif stripped == "spanning-tree bpdu-guard":
            interface.bpdu_guard = ConfigState.ENABLED
            interface.bpdu_guard_evidence = source_line
        elif stripped == "no spanning-tree bpdu-guard":
            interface.bpdu_guard = ConfigState.DISABLED
            interface.bpdu_guard_evidence = source_line
        else:
            config.unparsed_lines.append(source_line)
            return
        ArubaAOSCXParser._record_supported(config, source_line)

    @staticmethod
    def _parse_vlan_line(
        stripped: str,
        source_line: SourceLine,
        vlan_id: int,
        config: ParsedConfig,
    ) -> None:
        if stripped == "dhcpv4-snooping":
            config.dhcp_snooping_vlans.add(vlan_id)
            config.dhcp_snooping_vlan_evidence[vlan_id] = source_line
        elif stripped == "no dhcpv4-snooping":
            config.dhcp_snooping_vlans.discard(vlan_id)
            config.dhcp_snooping_vlan_evidence.pop(vlan_id, None)
        elif stripped == "arp inspection":
            config.dai_vlans.add(vlan_id)
            config.dai_vlan_evidence[vlan_id] = source_line
        elif stripped == "no arp inspection":
            config.dai_vlans.discard(vlan_id)
            config.dai_vlan_evidence.pop(vlan_id, None)
        else:
            config.unparsed_lines.append(source_line)
            return
        ArubaAOSCXParser._record_supported(config, source_line)

    @staticmethod
    def _record_supported(config: ParsedConfig, line: SourceLine) -> None:
        ArubaAOSCXParser._record_coverage(
            config, line, CoverageClass.SUPPORTED_RELEVANT
        )

    @staticmethod
    def _record_coverage(
        config: ParsedConfig,
        line: SourceLine,
        classification: CoverageClass,
    ) -> None:
        if line.line_number in config.parsed_line_coverage:
            raise ValueError(
                f"duplicate coverage classification for line "
                f"{line.line_number}"
            )
        config.parsed_line_coverage[line.line_number] = classification
