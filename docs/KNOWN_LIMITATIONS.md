# Known Limitations

## Parser Coverage V1

Parser Coverage V1 is line-oriented and is not vendor-version/default aware.
The selected platform’s small executable registry, rather than this prose
document, is the source of truth for declared unsupported command families.
Multi-line banner blocks are not modeled. See [Parser Coverage V1](PARSER_COVERAGE.md) for the
classification model, formulas, dedicated fixtures, and provisional Analysis
Confidence thresholds.

## ArubaOS-Switch / AOS-S first slice

The `aruba_aos_s` implementation is a limited Aruba 2930F first slice. Dynamic
AAA/RADIUS VLAN assignment is not modeled as effective or static VLAN
membership. A port with any static tagged membership is conservatively treated
as non-access (`TRUNK` in the normalized analyzer domain), so endpoint-access
rules do not evaluate it as an access port.

Port Security, IP Source Lockdown, STP edge/BPDU protection, and management
controls are deferred. Broad real configurations can consequently have `LOW`
Analysis Confidence; this describes incomplete analysis, not device
insecurity. A `DHCP-002` finding means a statically configured access VLAN is
outside the normalized DHCP Snooping scope. Configuration evidence alone does
not prove that the VLAN carries DHCP endpoints. See the concise
[AOS-S platform scope](ARUBA_AOS_S.md).

## Huawei VRP first slice

`huawei_vrp` is scoped to Huawei S5720 / V200R021 first-slice behavior. HYBRID
is `UNKNOWN`, not modeled as ACCESS or TRUNK; hybrid membership and trunk
VLAN scope are deferred. Interface-scoped DHCP Snooping is not represented
exactly or promoted to VLAN-wide protection. Interface-scoped DAI prevents
safe `DAI-001` support in the current VLAN-based model. IPSG, Port Security,
and management rules are also deferred and unassessed.

Substantial unknown syntax may yield `LOW` Analysis Confidence, indicating
limited analyzer coverage rather than device insecurity. `DHCP-002` identifies
a static ACCESS VLAN outside modeled DHCP Snooping scope; it does not prove
actual DHCP client usage. See [Huawei VRP scope](HUAWEI_VRP.md).

## PORTSEC-001 — Peer consistency heuristic

PORTSEC-001 uses at least one Port Security-enabled interface within the
same explicit access VLAN as a config-level policy intent signal.

The rule does not perform majority or minority analysis. For example, a VLAN
with 1 protected and 23 unprotected ports is evaluated using the same
consistency model as a VLAN with 23 protected and 1 unprotected port.

Consequently, a finding does not prove that the affected interfaces are
misconfigured. A protected interface may have a specialized role that is not
shared by its peers.

The static model does not currently evaluate 802.1X, NAC, MAB, or other
compensating access controls.

Interfaces with `NOT_CONFIGURED` and explicitly `DISABLED` Port Security are
placed in the same affected group for coverage-consistency analysis. The
explicit disabled state remains distinguishable through its source evidence.

The rule uses `MEDIUM` confidence because of these limitations. Its heuristic
may be recalibrated when representative configuration corpora and additional
access-control context become available.

## DHCP-003 — Endpoint-role verification

The Cisco safe configuration example preserves ACCESS mode/VLAN and removes
DHCP Snooping trust with `no ip dhcp snooping trust`. Operators must still
verify that the interface is endpoint-facing rather than an authorized DHCP
server path before applying the example.

## STP-001 — Initial effective-state scope

STP-001 evaluates PortFast edge intent only on interfaces explicitly parsed as
access ports. PortFast trunk and other platform-specific PortFast variants are
outside the initial scope. Unrecognized syntax remains unparsed rather than
being inferred as enabled or disabled.

## DAI-001 — One-way DHCP Snooping correlation

DAI-001 checks only for DHCP Snooping-protected endpoint VLANs that lack
Dynamic ARP Inspection coverage. It does not check the reverse direction:
DAI configured on a VLAN without DHCP Snooping backing or binding context.

That reverse condition may introduce availability, false-deny, or connectivity
risks when binding information is incomplete, but it requires a separate
future rule or correlation check.

The static model does not yet fully evaluate statically addressed hosts, ARP
ACLs, or other compensating ARP-validation mechanisms.

## IPSG-001 — Basic DHCP-backed source validation

IPSG-001 evaluates basic IP Source Guard coverage on endpoint access
interfaces in DHCP Snooping-protected VLANs. The basic interface-level
`ip verify source` and `no ip verify source` syntax has been verified for
relevant Cisco IOS XE Catalyst platforms, including the Catalyst 3650- and
9200-class documentation used during research.

Catalyst 2960-X and 2960-XR use classic Cisco IOS 15.2E rather than Cisco IOS
XE and may expose additional `ip verify source [...]` option syntax. Other
Catalyst families and releases may also expose different IPSG command forms.
These platform-specific variants are not fully modeled by the current parser.

The parser currently recognizes only the verified exact basic forms
`ip verify source` and `no ip verify source`. Unsupported variants may remain
in `unparsed_lines`. Forms such as `ip verify source port-security`,
`ip verify source mac-check`, and device-tracking-based source guards are not
fully analyzed in the initial MVP.

Static IP/source bindings and other compensating source-validation mechanisms
are not yet fully modeled. A DHCP Snooping-protected VLAN does not by itself
prove that organizational policy requires IP Source Guard, so the rule uses
`MEDIUM` confidence. Reverse and configuration-health scenarios remain topics
for separate future rules.

## MGMT-001 — Explicit VTY Telnet allowance only

MGMT-001 reports only VTY ranges that explicitly allow Telnet through a
supported `transport input` command. When `transport input` is absent, the
rule does not infer platform- or release-specific defaults.

Management reachability, VTY `access-class`, management VRFs and interfaces,
ACLs, firewalls, and out-of-band isolation are not yet included in exposure
assessment. SSH server availability and version, authentication methods, AAA,
key strength, and SSHv1 versus SSHv2 are outside this rule's scope.

Unsupported VTY transport syntax is retained as unparsed/unknown rather than
assumed safe. Authoritative replacement semantics for repeated
`transport input` directives in the same VTY block were not established for
this MVP, so repeated directives are also treated as ambiguous and do not
produce a definitive MGMT-001 finding.

For `transport input all`, the normalized protocol set represents only the
security-relevant subset currently modeled by the analyzer (including SSH and
Telnet); it is not intended to be an exhaustive inventory of every Cisco
terminal transport protocol.

## MGMT-002 — Explicit standard HTTP server enablement only

MGMT-002 intentionally reports only explicit `ip http server` configuration.
Cisco HTTP-server defaults vary by platform and release. Cisco Catalyst
2960-X IOS 15.2(6)E documentation used during research explicitly documents
the standard HTTP server as enabled in its default SSL configuration. Cisco
IOS-XE Catalyst 3650 documentation used during research describes the
standard HTTP server as typically disabled by default.

Therefore, a device whose HTTP service is active solely because of
platform/release default behavior may not be reported by MGMT-002. `HIGH`
confidence describes the reliability of a produced explicit finding; it does
not mean detection coverage is complete across Cisco platforms. Default-aware
interpretation will require platform/release identification.

Management reachability, HTTP ACL/access-class, authentication configuration,
and HTTPS TLS/certificate quality are not evaluated.

## DISCOVERY-001 — Explicit advertisement potential only

The Cisco first slice requires explicit global and interface enablement for
CDP or LLDP transmission. It does not infer Catalyst 2960-X default-enabled
CDP behavior throughout the broader Cisco IOS/IOS-XE scope. Omission remains
unknown, so default-driven advertisement may not be reported. Repeated
identical commands are accepted; conflicting explicit state remains unknown.

Only explicit ACCESS interfaces are eligible, without requiring an access
VLAN. ACCESS is an endpoint-role approximation: phones and other managed
endpoints may legitimately need discovery. Findings describe configured
advertisement potential, not observed packets or verified operational links.
TRUNK/UNKNOWN interfaces are excluded. LLDP receive does not create or
suppress transmit exposure, and is not normalized in this slice.

Remediation disables only the reported advertisement protocol(s) on the
interface. It does not disable discovery globally, LLDP receive, or change
mode/VLAN. Unverified reset forms, timers, TLVs and interface-range discovery
configuration remain outside supported syntax; this is a running-config
slice, not a command-script interpreter. Other platforms remain unassessed.

## Future default-aware controls

Broader CDP/LLDP analysis would require default-aware
interpretation. Absence-based detection must only be introduced when the
vendor/platform/release default has been authoritatively verified and the
analyzed device profile is known with sufficient confidence.
