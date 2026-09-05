from src.domain.models import (
    ConfigState,
    CoverageClass,
    InterfaceConfig,
    InterfaceMode,
    ParsedConfig,
    SourceLine,
)


class HuaweiVRPParser:
    vendor = "huawei_vrp"

    def parse(self, raw_text: str) -> ParsedConfig:
        config = ParsedConfig(vendor=self.vendor)
        current_vlan: int | None = None
        current_interface: InterfaceConfig | None = None
        pending_access_vlans: dict[str, tuple[int, SourceLine]] = {}

        for line_number, raw_line in enumerate(raw_text.splitlines(), 1):
            stripped = raw_line.strip()
            if not stripped:
                continue

            source_line = SourceLine(line_number, raw_line.rstrip())
            if stripped == "#":
                current_vlan = None
                current_interface = None
                self._record_coverage(
                    config,
                    source_line,
                    CoverageClass.OUT_OF_SCOPE,
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

            if raw_line[:1].isspace() and current_interface is not None:
                current_interface.raw_lines.append(source_line)
                self._parse_interface_line(
                    stripped,
                    source_line,
                    current_interface,
                    pending_access_vlans,
                    config,
                )
                continue

            if raw_line[:1].isspace():
                config.unparsed_lines.append(source_line)
                continue

            current_vlan = None
            current_interface = None

            if stripped.startswith("sysname "):
                hostname = stripped.removeprefix("sysname ").strip()
                if not hostname or any(
                    character.isspace() for character in hostname
                ):
                    config.unparsed_lines.append(source_line)
                    continue
                config.hostname = hostname
                self._record_coverage(
                    config,
                    source_line,
                    CoverageClass.OUT_OF_SCOPE,
                )
            elif stripped.startswith("vlan "):
                vlan_text = stripped.removeprefix("vlan ").strip()
                try:
                    current_vlan = self._parse_vlan_id(vlan_text)
                except ValueError:
                    config.unparsed_lines.append(source_line)
                    continue
                self._record_supported(config, source_line)
            elif stripped.startswith("interface "):
                interface_name = stripped.removeprefix("interface ").strip()
                if not interface_name or any(
                    character.isspace() for character in interface_name
                ):
                    config.unparsed_lines.append(source_line)
                    continue
                current_interface = InterfaceConfig(
                    name=interface_name,
                    declaration_evidence=source_line,
                    port_security=ConfigState.UNKNOWN,
                    ip_source_guard=ConfigState.UNKNOWN,
                    raw_lines=[source_line],
                )
                config.interfaces.append(current_interface)
                self._record_supported(config, source_line)
            elif stripped == "dhcp snooping enable":
                config.dhcp_snooping_global = ConfigState.ENABLED
                config.dhcp_snooping_global_evidence = source_line
                self._record_supported(config, source_line)
            elif stripped == "undo dhcp snooping enable":
                config.dhcp_snooping_global = ConfigState.DISABLED
                config.dhcp_snooping_global_evidence = source_line
                self._record_supported(config, source_line)
            elif stripped == "stp bpdu-protection":
                config.bpdu_guard_default = ConfigState.ENABLED
                config.bpdu_guard_default_evidence = source_line
                self._record_supported(config, source_line)
            else:
                config.unparsed_lines.append(source_line)

        self._finalize_access_vlans(config, pending_access_vlans)
        return config

    @classmethod
    def _parse_vlan_line(
        cls,
        stripped: str,
        source_line: SourceLine,
        vlan_id: int,
        config: ParsedConfig,
    ) -> None:
        if stripped == "dhcp snooping enable":
            config.dhcp_snooping_vlans.add(vlan_id)
            config.dhcp_snooping_vlan_evidence[vlan_id] = source_line
            cls._record_supported(config, source_line)
        elif stripped == "undo dhcp snooping enable":
            config.dhcp_snooping_vlans.discard(vlan_id)
            config.dhcp_snooping_vlan_evidence.pop(vlan_id, None)
            cls._record_supported(config, source_line)
        else:
            config.unparsed_lines.append(source_line)

    @classmethod
    def _parse_interface_line(
        cls,
        stripped: str,
        source_line: SourceLine,
        interface: InterfaceConfig,
        pending_access_vlans: dict[str, tuple[int, SourceLine]],
        config: ParsedConfig,
    ) -> None:
        if stripped == "port link-type access":
            interface.mode = InterfaceMode.ACCESS
            interface.mode_evidence = source_line
        elif stripped == "port link-type trunk":
            interface.mode = InterfaceMode.TRUNK
            interface.mode_evidence = source_line
        elif stripped == "port link-type hybrid":
            interface.mode = InterfaceMode.UNKNOWN
            interface.mode_evidence = source_line
        elif stripped.startswith("port default vlan "):
            vlan_text = stripped.removeprefix("port default vlan ").strip()
            try:
                vlan_id = cls._parse_vlan_id(vlan_text)
            except ValueError:
                config.unparsed_lines.append(source_line)
                return
            pending_access_vlans[interface.name] = (vlan_id, source_line)
        elif stripped == "dhcp snooping trusted":
            interface.dhcp_snooping_trust = ConfigState.ENABLED
            interface.dhcp_snooping_trust_evidence = source_line
        elif stripped == "stp edged-port enable":
            interface.portfast = ConfigState.ENABLED
            interface.portfast_evidence = source_line
        elif stripped == "undo stp edged-port":
            interface.portfast = ConfigState.DISABLED
            interface.portfast_evidence = source_line
        else:
            config.unparsed_lines.append(source_line)
            return
        cls._record_supported(config, source_line)

    @staticmethod
    def _finalize_access_vlans(
        config: ParsedConfig,
        pending_access_vlans: dict[str, tuple[int, SourceLine]],
    ) -> None:
        for interface in config.interfaces:
            if interface.mode != InterfaceMode.ACCESS:
                interface.access_vlan = None
                interface.access_vlan_evidence = None
                continue
            pending = pending_access_vlans.get(interface.name)
            if pending is None:
                continue
            interface.access_vlan, interface.access_vlan_evidence = pending

    @staticmethod
    def _parse_vlan_id(vlan_text: str) -> int:
        vlan_id = int(vlan_text)
        if not 1 <= vlan_id <= 4094:
            raise ValueError("VLAN ID is outside 1-4094")
        return vlan_id

    @staticmethod
    def _record_supported(config: ParsedConfig, line: SourceLine) -> None:
        HuaweiVRPParser._record_coverage(
            config,
            line,
            CoverageClass.SUPPORTED_RELEVANT,
        )

    @staticmethod
    def _record_coverage(
        config: ParsedConfig,
        line: SourceLine,
        classification: CoverageClass,
    ) -> None:
        if line.line_number in config.parsed_line_coverage:
            raise ValueError(
                "duplicate coverage classification for line "
                f"{line.line_number}"
            )
        config.parsed_line_coverage[line.line_number] = classification
