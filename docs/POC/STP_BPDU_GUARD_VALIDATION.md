# STP BPDU Guard Defensive Lab Validation

Status: validated defensive PoC in an isolated lab.

## Topology

The validation used a switch access port, `Ethernet0/1` (`Et0/1`), assigned to
VLAN 10 and configured for PortFast. An isolated lab peer connected to that
port supplied the controlled BPDU stimulus. The same port, VLAN, and stimulus
were retained for the before/after comparison.

## Weak configuration

The initial access-port configuration enabled PortFast but did not enable BPDU
Guard:

```text
interface Ethernet0/1
 switchport access vlan 10
 switchport mode access
 spanning-tree portfast
```

The preserved configuration evidence is
[`evidence/stp_before.cfg`](evidence/stp_before.cfg).

## Before observation

With the weak configuration applied, the BPDU receive count was greater than
zero. The port remained connected and in the forwarding state after the
controlled BPDU stimulus. This demonstrated that the PortFast edge port lacked
the intended per-interface BPDU Guard protection.

## Analyzer before result

Analysis of the exported weak configuration reported `STP-001` with HIGH
severity and HIGH confidence.

## Remediation

Per-interface BPDU Guard was enabled while retaining the access VLAN, access
mode, and PortFast configuration:

```text
interface Ethernet0/1
 switchport access vlan 10
 switchport mode access
 spanning-tree portfast
 spanning-tree bpduguard enable
```

The preserved remediated configuration evidence is
[`evidence/stp_after.cfg`](evidence/stp_after.cfg).

## After observation

When the same controlled BPDU stimulus was repeated, the switch applied BPDU
Guard and placed `Et0/1` into the `err-disabled` state. The relevant Cisco log
excerpts recorded by the lab were exactly:

```text
%SPANTREE-2-BLOCK_BPDUGUARD
%PM-4-ERR_DISABLE
```

## Analyzer after result

Analysis of the exported remediated configuration returned `No findings.`

## Conclusion

The defensive transition matched both sides of the validation contract. Before
remediation, the edge port accepted BPDUs while remaining connected/forwarding
and the analyzer reported `STP-001` HIGH/HIGH. After enabling BPDU Guard, the
same stimulus caused the port to become `err-disabled`, the Cisco BPDU Guard
and error-disable events were observed, and the analyzer returned no findings.

## DHCP Snooping investigation note

The DHCP Snooping experiment is **not yet validated / investigation**. It must
not be represented as a successful PoC. The observed attempt did not provide
sufficient evidence for the validation contract; this result is specific to
the tested setup and does not establish a general platform-support conclusion.
