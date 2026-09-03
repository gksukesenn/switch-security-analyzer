import re

from src.domain.models import (
    ConfigState,
    CoverageClass,
    InterfaceConfig,
    InterfaceMode,
    ParsedConfig,
    SourceLine,
)
from src.domain.vendors import Vendor


class ArubaAOSSParser:
    def parse(self, raw_text: str) -> ParsedConfig:
        config = ParsedConfig(vendor=Vendor.ARUBA_AOS_S.value)
        interfaces: dict[str, InterfaceConfig] = {}
        untagged_memberships: dict[str, list[tuple[int, SourceLine]]] = {}
        tagged_memberships: dict[str, list[SourceLine]] = {}
        current_vlan: int | None = None
        current_interface: InterfaceConfig | None = None

        for line_number, raw_line in enumerate(raw_text.splitlines(), 1):
            stripped = raw_line.strip()
            if not stripped:
                continue

            source_line = SourceLine(line_number, raw_line.rstrip())
            if stripped == "!":
                current_vlan = None
                current_interface = None
                continue
            if stripped in ("exit", "end"):
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
                    interfaces,
                    untagged_memberships,
                    tagged_memberships,
                )
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

            current_vlan = None
            current_interface = None

            if stripped.startswith("vlan "):
                vlan_text = stripped.removeprefix("vlan ").strip()
                try:
                    current_vlan = self._parse_vlan_id(vlan_text)
                    self._record_supported(config, source_line)
                except ValueError:
                    config.unparsed_lines.append(source_line)
            elif stripped.startswith("interface "):
                interface_name = stripped.removeprefix("interface ").strip()
                if not interface_name or any(
                    character.isspace() for character in interface_name
                ):
                    config.unparsed_lines.append(source_line)
                    continue
                current_interface = self._interface_for(
                    interface_name,
                    source_line,
                    config,
                    interfaces,
                )
                current_interface.declaration_evidence = source_line
                self._append_raw_line(current_interface, source_line)
                self._record_supported(config, source_line)
            elif stripped == "dhcp-snooping":
                config.dhcp_snooping_global = ConfigState.ENABLED
                config.dhcp_snooping_global_evidence = source_line
                self._record_supported(config, source_line)
            elif stripped == "no dhcp-snooping":
                config.dhcp_snooping_global = ConfigState.DISABLED
                config.dhcp_snooping_global_evidence = source_line
                self._record_supported(config, source_line)
            elif stripped.startswith("dhcp-snooping vlan "):
                self._parse_vlan_scope(
                    stripped.removeprefix("dhcp-snooping vlan "),
                    source_line,
                    config,
                    config.dhcp_snooping_vlans,
                    config.dhcp_snooping_vlan_evidence,
                    remove=False,
                )
            elif stripped.startswith("no dhcp-snooping vlan "):
                self._parse_vlan_scope(
                    stripped.removeprefix("no dhcp-snooping vlan "),
                    source_line,
                    config,
                    config.dhcp_snooping_vlans,
                    config.dhcp_snooping_vlan_evidence,
                    remove=True,
                )
            elif stripped.startswith("dhcp-snooping trust "):
                self._parse_global_trust(
                    stripped.removeprefix("dhcp-snooping trust "),
                    source_line,
                    config,
                    interfaces,
                    ConfigState.ENABLED,
                )
            elif stripped.startswith("no dhcp-snooping trust "):
                self._parse_global_trust(
                    stripped.removeprefix("no dhcp-snooping trust "),
                    source_line,
                    config,
                    interfaces,
                    ConfigState.DISABLED,
                )
            elif stripped.startswith("arp-protect vlan "):
                self._parse_vlan_scope(
                    stripped.removeprefix("arp-protect vlan "),
                    source_line,
                    config,
                    config.dai_vlans,
                    config.dai_vlan_evidence,
                    remove=False,
                )
            elif stripped.startswith("no arp-protect vlan "):
                self._parse_vlan_scope(
                    stripped.removeprefix("no arp-protect vlan "),
                    source_line,
                    config,
                    config.dai_vlans,
                    config.dai_vlan_evidence,
                    remove=True,
                )
            else:
                config.unparsed_lines.append(source_line)

        self._finalize_interface_modes(
            interfaces,
            untagged_memberships,
            tagged_memberships,
        )
        return config

    @classmethod
    def _parse_vlan_line(
        cls,
        stripped: str,
        source_line: SourceLine,
        vlan_id: int,
        config: ParsedConfig,
        interfaces: dict[str, InterfaceConfig],
        untagged_memberships: dict[str, list[tuple[int, SourceLine]]],
        tagged_memberships: dict[str, list[SourceLine]],
    ) -> None:
        if stripped == "dhcp-snooping":
            config.dhcp_snooping_vlans.add(vlan_id)
            config.dhcp_snooping_vlan_evidence[vlan_id] = source_line
            cls._record_supported(config, source_line)
            return
        if stripped == "no dhcp-snooping":
            config.dhcp_snooping_vlans.discard(vlan_id)
            config.dhcp_snooping_vlan_evidence.pop(vlan_id, None)
            cls._record_supported(config, source_line)
            return

        membership_type, separator, port_text = stripped.partition(" ")
        if not separator or membership_type not in ("untagged", "tagged"):
            config.unparsed_lines.append(source_line)
            return
        try:
            port_names = cls._parse_port_list(port_text)
        except ValueError:
            config.unparsed_lines.append(source_line)
            return

        for port_name in port_names:
            interface = cls._interface_for(
                port_name,
                source_line,
                config,
                interfaces,
            )
            cls._append_raw_line(interface, source_line)
            if membership_type == "untagged":
                untagged_memberships.setdefault(port_name, []).append(
                    (vlan_id, source_line)
                )
            else:
                tagged_memberships.setdefault(port_name, []).append(source_line)
        cls._record_supported(config, source_line)

    @classmethod
    def _parse_interface_line(
        cls,
        stripped: str,
        source_line: SourceLine,
        interface: InterfaceConfig,
        config: ParsedConfig,
    ) -> None:
        if stripped == "dhcp-snooping trust":
            interface.dhcp_snooping_trust = ConfigState.ENABLED
            interface.dhcp_snooping_trust_evidence = source_line
            cls._record_supported(config, source_line)
        elif stripped == "no dhcp-snooping trust":
            interface.dhcp_snooping_trust = ConfigState.DISABLED
            interface.dhcp_snooping_trust_evidence = source_line
            cls._record_supported(config, source_line)
        else:
            config.unparsed_lines.append(source_line)

    @classmethod
    def _parse_global_trust(
        cls,
        port_text: str,
        source_line: SourceLine,
        config: ParsedConfig,
        interfaces: dict[str, InterfaceConfig],
        state: ConfigState,
    ) -> None:
        try:
            port_names = cls._parse_port_list(port_text)
        except ValueError:
            config.unparsed_lines.append(source_line)
            return

        for port_name in port_names:
            interface = cls._interface_for(
                port_name,
                source_line,
                config,
                interfaces,
            )
            interface.dhcp_snooping_trust = state
            interface.dhcp_snooping_trust_evidence = source_line
            cls._append_raw_line(interface, source_line)
        cls._record_supported(config, source_line)

    @classmethod
    def _parse_vlan_scope(
        cls,
        vlan_text: str,
        source_line: SourceLine,
        config: ParsedConfig,
        vlan_ids: set[int],
        evidence: dict[int, SourceLine],
        *,
        remove: bool,
    ) -> None:
        try:
            parsed_vlan_ids = cls._parse_vlan_expression(vlan_text)
        except ValueError:
            config.unparsed_lines.append(source_line)
            return

        if remove:
            vlan_ids.difference_update(parsed_vlan_ids)
            for vlan_id in parsed_vlan_ids:
                evidence.pop(vlan_id, None)
        else:
            vlan_ids.update(parsed_vlan_ids)
            for vlan_id in parsed_vlan_ids:
                evidence[vlan_id] = source_line
        cls._record_supported(config, source_line)

    @staticmethod
    def _parse_vlan_expression(vlan_text: str) -> set[int]:
        tokens = vlan_text.split()
        if not tokens:
            raise ValueError("empty VLAN expression")

        vlan_ids: set[int] = set()
        for token in tokens:
            if "-" not in token:
                vlan_ids.add(ArubaAOSSParser._parse_vlan_id(token))
                continue
            range_parts = token.split("-")
            if len(range_parts) != 2:
                raise ValueError("malformed VLAN range")
            start = ArubaAOSSParser._parse_vlan_id(range_parts[0])
            end = ArubaAOSSParser._parse_vlan_id(range_parts[1])
            if start > end:
                raise ValueError("descending VLAN range")
            vlan_ids.update(range(start, end + 1))
        return vlan_ids

    @staticmethod
    def _parse_vlan_id(vlan_text: str) -> int:
        vlan_id = int(vlan_text)
        if not 1 <= vlan_id <= 4094:
            raise ValueError("VLAN ID is outside 1-4094")
        return vlan_id

    @staticmethod
    def _parse_port_list(port_text: str) -> list[str]:
        port_names: list[str] = []
        for item in port_text.replace(" ", ",").split(","):
            if not item:
                raise ValueError("empty port-list item")
            if "-" not in item:
                port_names.append(item)
                continue
            start_text, separator, end_text = item.partition("-")
            if not separator or "-" in end_text:
                raise ValueError("malformed port range")
            start_match = re.fullmatch(r"(.*?)(\d+)", start_text)
            end_match = re.fullmatch(r"(.*?)(\d+)", end_text)
            if start_match is None or end_match is None:
                raise ValueError("unsupported port range")
            if start_match.group(1) != end_match.group(1):
                raise ValueError("port range prefixes differ")
            start = int(start_match.group(2))
            end = int(end_match.group(2))
            if start > end:
                raise ValueError("descending port range")
            prefix = start_match.group(1)
            port_names.extend(f"{prefix}{number}" for number in range(start, end + 1))
        return port_names

    @staticmethod
    def _interface_for(
        name: str,
        evidence: SourceLine,
        config: ParsedConfig,
        interfaces: dict[str, InterfaceConfig],
    ) -> InterfaceConfig:
        interface = interfaces.get(name)
        if interface is not None:
            return interface
        interface = InterfaceConfig(
            name=name,
            declaration_evidence=evidence,
            port_security=ConfigState.UNKNOWN,
            ip_source_guard=ConfigState.UNKNOWN,
            portfast=ConfigState.UNKNOWN,
            bpdu_guard=ConfigState.UNKNOWN,
            raw_lines=[evidence],
        )
        interfaces[name] = interface
        config.interfaces.append(interface)
        return interface

    @staticmethod
    def _append_raw_line(
        interface: InterfaceConfig,
        source_line: SourceLine,
    ) -> None:
        if source_line not in interface.raw_lines:
            interface.raw_lines.append(source_line)

    @staticmethod
    def _finalize_interface_modes(
        interfaces: dict[str, InterfaceConfig],
        untagged_memberships: dict[str, list[tuple[int, SourceLine]]],
        tagged_memberships: dict[str, list[SourceLine]],
    ) -> None:
        for name, interface in interfaces.items():
            tagged_evidence = tagged_memberships.get(name, [])
            if tagged_evidence:
                interface.mode = InterfaceMode.TRUNK
                interface.mode_evidence = tagged_evidence[0]
                interface.access_vlan = None
                interface.access_vlan_evidence = None
                continue

            memberships = untagged_memberships.get(name, [])
            vlan_ids = {vlan_id for vlan_id, _ in memberships}
            if len(vlan_ids) != 1:
                interface.mode = InterfaceMode.UNKNOWN
                interface.mode_evidence = None
                interface.access_vlan = None
                interface.access_vlan_evidence = None
                continue

            vlan_id, membership_evidence = memberships[-1]
            interface.mode = InterfaceMode.ACCESS
            interface.mode_evidence = membership_evidence
            interface.access_vlan = vlan_id
            interface.access_vlan_evidence = membership_evidence

    @staticmethod
    def _record_supported(config: ParsedConfig, line: SourceLine) -> None:
        ArubaAOSSParser._record_coverage(
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
