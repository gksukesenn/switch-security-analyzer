# ArubaOS-Switch first-slice scope

## Platform and composition

The explicit vendor identifier is `aruba_aos_s`. The initial platform scope
is the Aruba 2930F family, using a narrowly documented ArubaOS-Switch (AOS-S)
16.10/16.11 syntax slice.

ArubaOS-Switch is not Aruba AOS-CX. The analyzer therefore selects separate
AOS-S parser, safe-configuration renderer, and coverage-registry
implementations. It does not auto-detect syntax or fall back to AOS-CX or
Cisco components.

## Supported normalized syntax

The first slice normalizes:

- global DHCP Snooping enable and disable state;
- DHCP Snooping VLAN scope, including whitespace-separated VLAN IDs and
  ranges;
- VLAN-context DHCP Snooping state;
- static VLAN-centric `tagged` and `untagged` port membership;
- interface-context and global port-list DHCP Snooping trust state; and
- Dynamic ARP Protection (`arp-protect`) VLAN scope.

Exact `SourceLine` provenance is retained for supported normalized state.

## Rule-assessment boundary

Where the required static evidence is present, the current slice can assess
`DHCP-001`, `DHCP-002`, `DHCP-003`, and `DAI-001`.

`PORTSEC-001`, `IPSG-001`, `STP-001`, `MGMT-001`, and `MGMT-002` are deferred.
Unsupported interface security states remain `UNKNOWN`, so the existing rules
do not produce absence-based findings for controls the parser did not assess.
The unchanged scoring model still uses all ten registered rules as its
denominator; a limited AOS-S analysis may therefore report score and risk as
`N/A`.

## Conservative VLAN interpretation

- One static untagged VLAN and no tagged membership becomes `ACCESS` with an
  `access_vlan`.
- Any tagged membership becomes conservatively non-access (`TRUNK` in the
  current normalized domain model) with no `access_vlan`.
- Conflicting static untagged memberships remain non-assessable.
- Dynamic AAA/RADIUS VLAN assignment is not converted into a static
  `access_vlan`.

`TRUNK` here is an analyzer-domain approximation used to exclude tagged ports
from endpoint-access rules. It does not claim that AOS-S uses Cisco
`switchport` terminology.

## External configuration validation

The implementation was manually validated against a representative external
Aruba 2930F running configuration. The configuration and all identifying or
sensitive material remain outside this repository.

The validation confirmed that DHCP Snooping VLAN ranges expanded correctly,
trusted tagged uplinks were excluded from `DHCP-003`, and dynamic AAA/RADIUS
VLAN policy was not mistaken for static endpoint membership. It completed
without a parser or rule-semantic bug and was classified **PASSED WITH
DOCUMENTED LIMITATIONS**.

Broad real AOS-S configurations may still produce `LOW` Analysis Confidence
because many security-relevant and unknown command families intentionally
remain unmodeled. Analysis Confidence describes analysis completeness; it is
not a statement that the device is insecure. See
[Parser Coverage](PARSER_COVERAGE.md), [Scoring](SCORING.md), and
[Known Limitations](KNOWN_LIMITATIONS.md).

`DISCOVERY-001` is also unsupported; current first-slice assessment is at most
4/10. The external validation above describes its original execution.
