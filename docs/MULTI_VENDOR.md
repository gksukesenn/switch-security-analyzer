# Multi-platform architecture

Vendor selection is explicit. Only `POST /analyze` and the application
service's default argument retain `cisco_ios` as a backward-compatible default;
configuration syntax is not auto-detected. File uploads, batch devices, and
the HTTP CLI require an explicit vendor.

`VendorComponentSelector` selects four components together at application
composition time: **parser + renderer + coverage registry + supported rule
IDs**. Its explicit platform pipelines are:

| Identifier | Platform | Supported rule IDs |
|---|---|---|
| `cisco_ios` | Cisco IOS / IOS-XE | All nine registered rules |
| `aruba_aos_cx` | Aruba AOS-CX | `DHCP-001`, `DHCP-002`, `DHCP-003`, `DAI-001`, `STP-001` |
| `aruba_aos_s` | ArubaOS-Switch / AOS-S | `DHCP-001`, `DHCP-002`, `DHCP-003`, `DAI-001` |
| `huawei_vrp` | Huawei VRP / S5720 | `DHCP-001`, `DHCP-002`, `DHCP-003`, `STP-001` |

AOS-CX and AOS-S remain separate platforms, with separate parsers, renderers,
and coverage registries. The selector explicitly constructs component sets;
there is no dynamic plugin discovery. Unsupported vendors fail explicitly,
and no cross-vendor syntax fallback exists.

## Platform rule-support policy

`VendorComponents.supported_rule_ids` is an explicit capability set introduced
during Huawei Phase 1. `AnalysisApplicationService` validates that the set
contains only registered IDs, then evaluates supported rules against the
normalized configuration. Unsupported platform rules receive an empty
`RuleEvaluation` with `assessed_units=0`.

All nine registered rule IDs remain in evaluations and the scoring denominator.
Platform support does not guarantee config-level assessment: even a supported
rule needs applicable normalized evidence before it can assess units. This
policy requires no vendor-specific branches inside rule implementations.

AOS-CX can assess up to five rules, AOS-S up to four, and Huawei VRP up to four
in their first slices. The unchanged nine-rule denominator and eligibility
gate can therefore produce score/risk `N/A`. This reports incomplete
assessment, not a worse security result. See [AOS-CX scope](ARUBA_AOS_CX.md),
[AOS-S scope](ARUBA_AOS_S.md), [Huawei VRP scope](HUAWEI_VRP.md), and
[Scoring](SCORING.md).

## Normalization and rendering

- Detection logic remains on the normalized model.
- Each vendor parser provides `SourceLine` provenance alongside normalized
  field values. Rules must not scan raw vendor syntax when normalized
  provenance is available.
- Safe-configuration syntax is delegated to the selected renderer. The Cisco
  reference renderer preserves existing output; first-slice Aruba and Huawei
  renderers implement only their supported operations.
- Unavailable rendering returns `N/A`; Cisco syntax is never substituted as a
  cross-vendor fallback.

Batch Analysis can select any of the four platform pipelines in one request.
Each device's explicit vendor passes through the same single-device
application service; batch logic only aggregates returned results. It does
not auto-detect vendors or combine vendor scoring semantics. The separate
local/offline CLI continues to invoke the Cisco analyzer directly.
