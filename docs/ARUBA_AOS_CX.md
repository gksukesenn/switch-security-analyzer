# Aruba AOS-CX V1 scope

## Reference scope

The first vertical slice targets the documented Aruba AOS-CX 10.12/10.13
syntax subset for DHCPv4 Snooping, Dynamic ARP Inspection, Layer-2 access
interfaces, administrative edge ports, and BPDU Guard. It does not combine
unverified syntax from other Aruba operating systems.

Vendor selection is explicit (`aruba_aos_cx`). There is no syntax
auto-detection and no fallback to Cisco parser, renderer, or coverage logic.

## Supported rules and normalized state

The supported first-slice rules are DHCP-001, DHCP-002, DHCP-003, DAI-001, and
STP-001. The parser maps global and VLAN DHCPv4 Snooping, interface trust,
VLAN DAI, access mode/VLAN, admin-edge intent, and BPDU Guard to the shared
normalized model and records exact `SourceLine` provenance.

AOS-CX interfaces are Layer 2 by default. The documented `no routing` command
places an interface in access VLAN 1, while `vlan access <id>` creates an access
interface with that VLAN. The parser models those documented semantics without
inventing an unknown VLAN.

Port Security and IP Source Guard are outside this slice. Their interface
states are initialized to `UNKNOWN`, not `NOT_CONFIGURED`, so unsupported
controls do not create absence-based findings. MGMT-001 and MGMT-002 are also
outside this slice.

## Safe configuration rendering

The Aruba renderer supports:

- enabling DHCPv4 Snooping globally and for VLANs;
- adding a VLAN to DHCPv4 Snooping scope;
- removing DHCPv4 Snooping trust from an endpoint interface;
- enabling Dynamic ARP Inspection on a VLAN;
- enabling BPDU Guard on edge interfaces.

Port Security, IP Source Guard, VTY-to-SSH, and HTTP-server operations return
the deterministic string `N/A`. They never return Cisco syntax.

## Coverage and scoring

The Aruba registry classifies only the verified unsupported AOS-CX DAI
interface-trust family in unparsed lines. Other unknown syntax, including CLI
forms not verified for source lockdown, remains `UNKNOWN_RELEVANCE`.

Scoring uses the unchanged nine-rule denominator and existing assessment gate.
For the fully safe first-slice fixture, five rules are counted as assessed:
DHCP-001, DHCP-002, DHCP-003, DAI-001, and STP-001. The resulting assessment
ratio is 5/9 (approximately 55.6%), so the unchanged assessment gate reports
the posture score and risk level as `N/A`. IPSG-001 is not assessed because
its decisive interface state is `UNKNOWN`; it produces no finding. No
vendor-specific denominator or scoring exception is introduced.

Other known gaps include management controls, VLAN-level source lockdown, and
the AOS-CX Port Security command subset.

## Official references

- Aruba AOS-CX 10.13 IP Services Guides for global/VLAN DHCPv4 Snooping and
  interface trust commands.
- Aruba AOS-CX 10.12 CLI/IP Services Guides for Dynamic ARP Inspection.
- Aruba AOS-CX 10.13 Layer 2 Bridging Guides for access VLAN, routing mode,
  admin-edge, and BPDU Guard commands.
