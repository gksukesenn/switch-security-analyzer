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
