# Known Limitations

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
interfaces in DHCP Snooping-protected VLANs. Platform- and release-specific
forms such as `ip verify source port-security`, `ip verify source mac-check`,
and device-tracking-based source guards are not fully analyzed in the initial
MVP.

Static IP/source bindings and other compensating source-validation mechanisms
are not yet fully modeled. A DHCP Snooping-protected VLAN does not by itself
prove that organizational policy requires IP Source Guard, so the rule uses
`MEDIUM` confidence. Reverse and configuration-health scenarios remain topics
for separate future rules.
