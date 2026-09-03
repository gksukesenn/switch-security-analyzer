from src.domain.models import (
    ConfigState,
    CoverageClass,
    InterfaceConfig,
    InterfaceMode,
    ParsedConfig,
    SourceLine,
    VtyConfig,
)
from src.domain.vendors import Vendor


class CiscoIOSParser:
    def parse(self, raw_text: str) -> ParsedConfig:
        config = ParsedConfig(vendor=Vendor.CISCO_IOS.value)

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
                    self._record_coverage(
                        config, source_line, CoverageClass.OUT_OF_SCOPE
                    )

                elif stripped == "switchport mode access":
                    current_interface.mode = InterfaceMode.ACCESS
                    current_interface.mode_evidence = source_line
                    self._record_supported(config, source_line)

                elif stripped == "switchport mode trunk":
                    current_interface.mode = InterfaceMode.TRUNK
                    current_interface.mode_evidence = source_line
                    self._record_supported(config, source_line)

                elif stripped.startswith("switchport access vlan "):
                    vlan_text = stripped.removeprefix(
                        "switchport access vlan "
                    ).strip()

                    try:
                        current_interface.access_vlan = int(vlan_text)
                        current_interface.access_vlan_evidence = source_line
                        self._record_supported(config, source_line)
                    except ValueError:
                        config.unparsed_lines.append(source_line)

                elif stripped == "ip dhcp snooping trust":
                    current_interface.dhcp_snooping_trust = (
                        ConfigState.ENABLED
                    )
                    current_interface.dhcp_snooping_trust_evidence = source_line
                    self._record_supported(config, source_line)

                elif stripped == "no ip dhcp snooping trust":
                    current_interface.dhcp_snooping_trust = (
                        ConfigState.DISABLED
                    )
                    current_interface.dhcp_snooping_trust_evidence = source_line
                    self._record_supported(config, source_line)

                elif stripped == "switchport port-security":
                    current_interface.port_security = ConfigState.ENABLED
                    current_interface.port_security_evidence = source_line
                    self._record_supported(config, source_line)

                elif stripped == "no switchport port-security":
                    current_interface.port_security = ConfigState.DISABLED
                    current_interface.port_security_evidence = source_line
                    self._record_supported(config, source_line)

                elif stripped in (
                    "spanning-tree portfast",
                    "spanning-tree portfast edge",
                ):
                    current_interface.portfast = ConfigState.ENABLED
                    current_interface.portfast_evidence = source_line
                    self._record_supported(config, source_line)

                elif stripped == "spanning-tree bpduguard enable":
                    current_interface.bpdu_guard = ConfigState.ENABLED
                    current_interface.bpdu_guard_evidence = source_line
                    self._record_supported(config, source_line)

                elif stripped == "spanning-tree bpduguard disable":
                    current_interface.bpdu_guard = ConfigState.DISABLED
                    current_interface.bpdu_guard_evidence = source_line
                    self._record_supported(config, source_line)

                elif stripped == "no spanning-tree bpduguard":
                    current_interface.bpdu_guard = (
                        ConfigState.NOT_CONFIGURED
                    )
                    current_interface.bpdu_guard_evidence = source_line
                    self._record_supported(config, source_line)

                elif stripped == "ip verify source":
                    current_interface.ip_source_guard = ConfigState.ENABLED
                    current_interface.ip_source_guard_evidence = source_line
                    self._record_supported(config, source_line)

                elif stripped == "no ip verify source":
                    current_interface.ip_source_guard = ConfigState.DISABLED
                    current_interface.ip_source_guard_evidence = source_line
                    self._record_supported(config, source_line)

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
                    declaration_evidence=source_line,
                    raw_lines=[source_line],
                )

                config.interfaces.append(current_interface)
                self._record_supported(config, source_line)

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
                    declaration_evidence=source_line,
                    raw_lines=[source_line],
                )
                config.vty_lines.append(current_vty)
                self._record_supported(config, source_line)

            elif stripped.startswith("hostname "):
                config.hostname = stripped.removeprefix(
                    "hostname "
                ).strip()
                self._record_coverage(
                    config, source_line, CoverageClass.OUT_OF_SCOPE
                )

            elif stripped == "ip dhcp snooping":
                config.dhcp_snooping_global = ConfigState.ENABLED
                config.dhcp_snooping_global_evidence = source_line
                self._record_supported(config, source_line)

            elif stripped == "no ip dhcp snooping":
                config.dhcp_snooping_global = ConfigState.DISABLED
                config.dhcp_snooping_global_evidence = source_line
                self._record_supported(config, source_line)

            elif stripped == "ip http server":
                config.http_server = ConfigState.ENABLED
                config.http_server_evidence = source_line
                self._record_supported(config, source_line)

            elif stripped == "no ip http server":
                config.http_server = ConfigState.DISABLED
                config.http_server_evidence = source_line
                self._record_supported(config, source_line)

            elif stripped == "ip http secure-server":
                config.https_server = ConfigState.ENABLED
                config.https_server_evidence = source_line
                self._record_supported(config, source_line)

            elif stripped == "no ip http secure-server":
                config.https_server = ConfigState.DISABLED
                config.https_server_evidence = source_line
                self._record_supported(config, source_line)

            elif stripped.startswith("ip dhcp snooping vlan "):
                vlan_text = stripped.removeprefix(
                    "ip dhcp snooping vlan "
                ).strip()

                try:
                    vlan_ids = self._parse_vlan_expression(vlan_text)

                    config.dhcp_snooping_vlans.update(vlan_ids)
                    for vlan_id in vlan_ids:
                        config.dhcp_snooping_vlan_evidence[vlan_id] = (
                            source_line
                        )
                    self._record_supported(config, source_line)
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
                    self._record_supported(config, source_line)
                except ValueError:
                    config.unparsed_lines.append(source_line)

            elif stripped in (
                "spanning-tree portfast default",
                "spanning-tree portfast edge default",
            ):
                config.portfast_default = ConfigState.ENABLED
                config.portfast_default_evidence = source_line
                self._record_supported(config, source_line)

            elif stripped in (
                "no spanning-tree portfast default",
                "no spanning-tree portfast edge default",
            ):
                config.portfast_default = ConfigState.DISABLED
                config.portfast_default_evidence = source_line
                self._record_supported(config, source_line)

            elif stripped in (
                "spanning-tree portfast bpduguard default",
                "spanning-tree portfast edge bpduguard default",
            ):
                config.bpdu_guard_default = ConfigState.ENABLED
                config.bpdu_guard_default_evidence = source_line
                self._record_supported(config, source_line)

            elif stripped in (
                "no spanning-tree portfast bpduguard default",
                "no spanning-tree portfast edge bpduguard default",
            ):
                config.bpdu_guard_default = ConfigState.DISABLED
                config.bpdu_guard_default_evidence = source_line
                self._record_supported(config, source_line)

            else:
                config.unparsed_lines.append(source_line)

        return config

    @staticmethod
    def _parse_vlan_expression(vlan_text: str) -> set[int]:
        vlan_ids: set[int] = set()

        for item in vlan_text.split(","):
            item = item.strip()
            if not item:
                raise ValueError("empty VLAN expression item")

            if "-" not in item:
                vlan_ids.add(int(item))
                continue

            range_parts = item.split("-")
            if len(range_parts) != 2:
                raise ValueError("malformed VLAN range")

            start = int(range_parts[0].strip())
            end = int(range_parts[1].strip())
            if start > end:
                raise ValueError("descending VLAN range")

            vlan_ids.update(range(start, end + 1))

        return vlan_ids

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
        CiscoIOSParser._record_supported(config, source_line)

    @staticmethod
    def _record_supported(
        config: ParsedConfig,
        source_line: SourceLine,
    ) -> None:
        CiscoIOSParser._record_coverage(
            config,
            source_line,
            CoverageClass.SUPPORTED_RELEVANT,
        )

    @staticmethod
    def _record_coverage(
        config: ParsedConfig,
        source_line: SourceLine,
        classification: CoverageClass,
    ) -> None:
        if source_line.line_number in config.parsed_line_coverage:
            raise ValueError(
                f"duplicate coverage classification for line "
                f"{source_line.line_number}"
            )
        config.parsed_line_coverage[source_line.line_number] = classification
