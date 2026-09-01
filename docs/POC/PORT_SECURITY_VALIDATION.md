# Port Security Defensive Lab Validation

Status: validated defensive PoC in an isolated lab.

## Topology

The switch exposed two access ports in VLAN 10. `Ethernet0/1` was the protected
reference port. `Ethernet0/2` was the validation target connected to the
isolated lab endpoint. The before/after analysis and enforcement checks used
the same target interface and VLAN.

## Weak state

Port Security was configured on `Ethernet0/1` but absent from the target access
port, `Ethernet0/2`:

```text
interface Ethernet0/1
 switchport access vlan 10
 switchport mode access
 switchport port-security

interface Ethernet0/2
 switchport access vlan 10
 switchport mode access
```

The preserved weak configuration evidence is
[`evidence/portsec_before.cfg`](evidence/portsec_before.cfg).

## Analyzer before result

The analyzer reported `PORTSEC-001` with MEDIUM severity and MEDIUM confidence.
The `affected_interface` was `Ethernet0/2`.

## Remediation

Port Security was enabled on the target access port:

```text
interface Ethernet0/2
 switchport access vlan 10
 switchport mode access
 switchport port-security
```

The preserved remediated configuration evidence is
[`evidence/portsec_after.cfg`](evidence/portsec_after.cfg).

## Analyzer after result

Analysis of the remediated configuration returned `No findings.`

## Enforcement validation

The post-remediation switch state for `Et0/2` showed:

- Port Security: `Enabled`
- Violation Mode: `Shutdown`
- Maximum MAC Addresses: `1`
- Learned secure MAC: `5254.00a2.5681`

After the secure MAC had been learned, the controlled second-MAC stimulus used
MAC address `0211.2233.4455` on the isolated validation port.

The relevant Cisco violation log excerpts recorded by the lab were exactly:

```text
%PORT_SECURITY-2-PSECURE_VIOLATION
%PM-4-ERR_DISABLE
```

The resulting enforcement state was:

- `Et0/2`: `err-disabled`
- Port Status: `Secure-shutdown`
- Security Violation Count: `1`
- Test ping: `100% packet loss`

## Conclusion

The analyzer and switch enforcement transitions both matched the defensive
validation objective. Before remediation, the analyzer identified missing Port
Security on `Ethernet0/2` as `PORTSEC-001` MEDIUM/MEDIUM. After Port Security
was enabled, the analyzer returned no findings. The switch learned the expected
single secure MAC, rejected the controlled second MAC, emitted the Port
Security violation and error-disable events, placed `Et0/2` into
`Secure-shutdown`/`err-disabled`, counted one violation, and blocked the test
traffic.

## DHCP Snooping investigation note

The DHCP Snooping experiment remains **not validated / investigation** and is
not a successful validation. The observed attempt did not provide sufficient
acceptance evidence; that setup-specific result does not establish a general
platform-support limitation.
