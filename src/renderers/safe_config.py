from collections.abc import Iterable
from typing import Protocol

from src.utils import natural_sort_key


class SafeConfigRenderer(Protocol):
    def enable_dhcp_snooping(self, vlan_ids: Iterable[int]) -> str: ...

    def add_dhcp_snooping_vlan(self, vlan_id: int) -> str: ...

    def correct_trusted_access_interface(
        self,
        interface_name: str,
        access_vlan: int,
    ) -> str: ...

    def enable_dai_vlan(self, vlan_id: int) -> str: ...

    def enable_bpdu_guard(self, interface_names: Iterable[str]) -> str: ...

    def enable_port_security(self, interface_names: Iterable[str]) -> str: ...

    def enable_ip_source_guard(
        self,
        interface_names: Iterable[str],
    ) -> str: ...

    def restrict_vty_to_ssh(
        self,
        vty_ranges: Iterable[tuple[int, int]],
    ) -> str: ...

    def disable_insecure_http_server(self) -> str: ...


class CiscoSafeConfigRenderer:
    def enable_dhcp_snooping(self, vlan_ids: Iterable[int]) -> str:
        vlan_scope = [
            f"ip dhcp snooping vlan {vlan_id}"
            for vlan_id in sorted(vlan_ids)
        ]
        if not vlan_scope:
            vlan_scope.append("ip dhcp snooping vlan <intended-vlan-id>")
        return "\n".join(["ip dhcp snooping", *vlan_scope])

    def add_dhcp_snooping_vlan(self, vlan_id: int) -> str:
        return f"ip dhcp snooping\nip dhcp snooping vlan {vlan_id}"

    def correct_trusted_access_interface(
        self,
        interface_name: str,
        access_vlan: int,
    ) -> str:
        return (
            f"interface {interface_name}\n"
            " switchport mode access\n"
            f" switchport access vlan {access_vlan}"
        )

    def enable_dai_vlan(self, vlan_id: int) -> str:
        return f"ip arp inspection vlan {vlan_id}"

    def enable_bpdu_guard(self, interface_names: Iterable[str]) -> str:
        return self._interface_blocks(
            interface_names,
            "spanning-tree bpduguard enable",
        )

    def enable_port_security(self, interface_names: Iterable[str]) -> str:
        return self._interface_blocks(
            interface_names,
            "switchport port-security",
        )

    def enable_ip_source_guard(
        self,
        interface_names: Iterable[str],
    ) -> str:
        return self._interface_blocks(interface_names, "ip verify source")

    def restrict_vty_to_ssh(
        self,
        vty_ranges: Iterable[tuple[int, int]],
    ) -> str:
        return "\n!\n".join(
            f"line vty {start} {end}\n transport input ssh"
            for start, end in sorted(vty_ranges)
        )

    def disable_insecure_http_server(self) -> str:
        return "no ip http server"

    @staticmethod
    def _interface_blocks(
        interface_names: Iterable[str],
        command: str,
    ) -> str:
        return "\n!\n".join(
            f"interface {name}\n {command}"
            for name in sorted(interface_names, key=natural_sort_key)
        )


class ArubaSafeConfigRenderer:
    unavailable_text = "N/A"

    def enable_dhcp_snooping(self, vlan_ids: Iterable[int]) -> str:
        vlan_scope = [
            f"vlan {vlan_id}\n dhcpv4-snooping"
            for vlan_id in sorted(vlan_ids)
        ]
        if not vlan_scope:
            vlan_scope.append("vlan <intended-vlan-id>\n dhcpv4-snooping")
        return "\n".join(["dhcpv4-snooping", *vlan_scope])

    def add_dhcp_snooping_vlan(self, vlan_id: int) -> str:
        return (
            "dhcpv4-snooping\n"
            f"vlan {vlan_id}\n"
            " dhcpv4-snooping"
        )

    def correct_trusted_access_interface(
        self,
        interface_name: str,
        access_vlan: int,
    ) -> str:
        return (
            f"interface {interface_name}\n"
            " no dhcpv4-snooping trust"
        )

    def enable_dai_vlan(self, vlan_id: int) -> str:
        return f"vlan {vlan_id}\n arp inspection"

    def enable_bpdu_guard(self, interface_names: Iterable[str]) -> str:
        return self._interface_blocks(
            interface_names,
            "spanning-tree bpdu-guard",
        )

    def enable_port_security(self, interface_names: Iterable[str]) -> str:
        return self.unavailable_text

    def enable_ip_source_guard(
        self,
        interface_names: Iterable[str],
    ) -> str:
        return self.unavailable_text

    def restrict_vty_to_ssh(
        self,
        vty_ranges: Iterable[tuple[int, int]],
    ) -> str:
        return self.unavailable_text

    def disable_insecure_http_server(self) -> str:
        return self.unavailable_text

    @staticmethod
    def _interface_blocks(
        interface_names: Iterable[str],
        command: str,
    ) -> str:
        return "\n!\n".join(
            f"interface {name}\n {command}"
            for name in sorted(interface_names, key=natural_sort_key)
        )


class UnavailableSafeConfigRenderer:
    unavailable_text = "N/A"

    def enable_dhcp_snooping(self, vlan_ids: Iterable[int]) -> str:
        return self.unavailable_text

    def add_dhcp_snooping_vlan(self, vlan_id: int) -> str:
        return self.unavailable_text

    def correct_trusted_access_interface(
        self,
        interface_name: str,
        access_vlan: int,
    ) -> str:
        return self.unavailable_text

    def enable_dai_vlan(self, vlan_id: int) -> str:
        return self.unavailable_text

    def enable_bpdu_guard(self, interface_names: Iterable[str]) -> str:
        return self.unavailable_text

    def enable_port_security(self, interface_names: Iterable[str]) -> str:
        return self.unavailable_text

    def enable_ip_source_guard(
        self,
        interface_names: Iterable[str],
    ) -> str:
        return self.unavailable_text

    def restrict_vty_to_ssh(
        self,
        vty_ranges: Iterable[tuple[int, int]],
    ) -> str:
        return self.unavailable_text

    def disable_insecure_http_server(self) -> str:
        return self.unavailable_text


def default_safe_config_renderer() -> SafeConfigRenderer:
    """Return the Cisco renderer for V1 direct-rule compatibility only."""
    return CiscoSafeConfigRenderer()
