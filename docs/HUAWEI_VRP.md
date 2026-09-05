# Huawei VRP / S5720 first slice

| Scope | Value |
|---|---|
| Vendor identifier | `huawei_vrp` |
| Initial platform | Huawei S5720 family |
| Validated representative device | S5720-28X-LI-AC |
| Initial VRP scope | V200R021 first slice |

This is a bounded implementation, not a claim of support for every Huawei
switch or every VRP release. Select `huawei_vrp` explicitly through the API,
HTTP CLI, or the browser's **Huawei VRP (S5720 first slice)** option. There is
no vendor auto-detection or cross-vendor syntax fallback. The separate offline
CLI remains Cisco-only.

## Supported normalization

| Configuration syntax/context | Normalized meaning |
|---|---|
| `sysname` | Device name; out of security-analysis scope |
| Global `dhcp snooping enable` / `undo dhcp snooping enable` | Explicit global DHCP Snooping state |
| VLAN-context `dhcp snooping enable` / `undo dhcp snooping enable` | Adds/removes that VLAN's modeled DHCP Snooping scope |
| `port link-type access` | Explicit `ACCESS` mode |
| `port default vlan` | Access VLAN only when final interface mode is explicit `ACCESS` |
| `port link-type trunk` | Explicit `TRUNK` mode |
| Interface `dhcp snooping trusted` | Explicit DHCP Snooping trust |
| `stp edged-port enable` / `undo stp edged-port` | Explicit edge intent enabled/disabled |
| Global `stp bpdu-protection` | Modeled global BPDU protection for edge intent |

`port link-type hybrid` maps to `UNKNOWN` and is non-assessable as an endpoint
access port in the current normalized model. HYBRID is not equivalent to
Cisco ACCESS or TRUNK. Hybrid PVID/tagged/untagged membership is not currently
normalized, and trunk VLAN scope is deferred.

Interface-scoped DHCP Snooping is not represented exactly or treated as
VLAN-wide protection. Interface-scoped DAI is not converted into `dai_vlans`:
local interface protection cannot safely establish protection of an entire
VLAN. Unsupported syntax remains outside normalized security state.

## Rule support

| Rule | First-slice support |
|---|---|
| `DHCP-001` | Supported |
| `DHCP-002` | Supported |
| `DHCP-003` | Supported |
| `STP-001` | Supported |
| `DAI-001` | Deferred / unassessed |
| `IPSG-001` | Deferred / unassessed |
| `PORTSEC-001` | Deferred / unassessed |
| `MGMT-001` | Deferred / unassessed |
| `MGMT-002` | Deferred / unassessed |

The explicit platform rule-support policy keeps all nine rule IDs in
`evaluations`. Unsupported platform rules have no findings and
`assessed_units=0`; the scoring denominator remains nine. Platform support is
separate from config-level assessment: supported rules still need applicable
static evidence. There are no Huawei/vendor branches inside rule
implementations. See [multi-vendor architecture](MULTI_VENDOR.md) for the
canonical composition policy.

## Real-config validation

**REAL-CONFIG VALIDATION PASSED WITH DOCUMENTED LIMITATIONS**

The external instructor-provided S5720 configuration was checked without
adding the configuration or raw excerpts to this repository. The recorded
conclusions are limited to these non-sensitive observations:

- Global DHCP Snooping normalized correctly.
- VLAN scope 10, 601–620, 777 normalized correctly.
- ACCESS/TRUNK/HYBRID distinctions behaved conservatively.
- A trusted network-facing TRUNK did not create `DHCP-003`.
- Interface-scoped DAI did not become false VLAN-wide DAI state.
- STP edge intent was detected.
- Unsupported security families remained unassessed.

| Observed first-slice result | Value |
|---|---|
| Analysis confidence | LOW |
| Assessed rules | 4 / 9 |
| Score | N/A |
| Risk | N/A |

LOW confidence indicates limited analyzer coverage, not that the device
itself is insecure. Substantial unsupported or unknown syntax can remain;
see [Parser Coverage](PARSER_COVERAGE.md). Limited assessment legitimately
leaves score and risk unavailable under the unchanged [scoring gate](SCORING.md).

`DHCP-002` findings mean: **Static ACCESS VLAN outside the modeled DHCP
Snooping scope.** They do not establish that a VLAN actually uses DHCP;
that requires operational evidence. `STP-001` is a strong static finding
candidate where explicit ACCESS edge ports lacked effective modeled BPDU
Protection. These conclusions do not certify runtime behavior or broaden the
first-slice rule support matrix.
