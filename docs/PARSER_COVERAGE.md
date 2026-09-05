# Parser Coverage V1

Parser Coverage answers one device-level question: how much of the analyzer's
declared security-analysis scope was actually understood for this
configuration? It is not a security posture score and does not describe
whether the device is secure.

## Line classifications

Every nonblank configuration line other than the exact `!` separator belongs
to exactly one class.

- `SUPPORTED_RELEVANT`: the selected vendor parser successfully normalized a
  security control used by the supported model, or structural context required
  by that model.
- `UNSUPPORTED_RELEVANT`: the parser did not normalize the line, but the
  selected platform's executable coverage registry recognizes it as a declared
  analyzer scope gap.
- `OUT_OF_SCOPE`: the line is known not to contribute to the current security
  model. This allowlist is intentionally narrow.
- `UNKNOWN_RELEVANCE`: the parser did not normalize the line and the
  selected registry cannot classify its relevance reliably.

Parsed does not automatically mean relevant. For example, `hostname`, Huawei
`sysname`, and interface `description` are retained by the parser but no active rule,
effective-state calculation, evidence builder, or affected-resource selection
reads their values. They are therefore `OUT_OF_SCOPE`. Conversely,
`interface` and `line vty` are `SUPPORTED_RELEVANT` because they create parent
context required to normalize security state.

The explicitly selected vendor parser records `SUPPORTED_RELEVANT` or
`OUT_OF_SCOPE` for successful branches. Failed branches do not record
successful coverage. Only parser-produced unparsed lines are offered to that
platform's small declarative registry. The selected parser plus its
corresponding coverage registry is the executable classification source of
truth. Registries identify declared command-family gaps but never produce
normalized security state or interpret nested syntax. Unmatched unparsed
lines remain `UNKNOWN_RELEVANCE`.

These classifications apply to all four explicit platforms: Cisco IOS /
IOS-XE, Aruba AOS-CX, ArubaOS-Switch / AOS-S, and Huawei VRP. Huawei `#`
context separators are classified as `OUT_OF_SCOPE`.

## Metrics

Let `S`, `U`, `O`, and `X` be the four class counts respectively.

```text
parser_coverage = S / (S + U), when S + U > 0
unknown_ratio   = X / (S + U + X), when S + U + X > 0
```

Coverage is N/A when `S + U == 0`; it is never reported as 100% in that case.
The unknown ratio is zero when its denominator is zero. `OUT_OF_SCOPE` is
excluded from both denominators so boilerplate cannot dilute uncertainty.

## Analysis Confidence V1

Analysis Confidence describes device-level analysis completeness. It is a
dedicated type and is distinct from `Finding.confidence`, which describes
confidence in one specific finding.

Base confidence is:

- coverage `>= 0.80`: `HIGH`
- `0.60 <= coverage < 0.80`: `MEDIUM`
- coverage `< 0.60`: `LOW`
- coverage N/A: `UNKNOWN`

The unknown penalty is:

- unknown ratio `<= 0.20`: no downgrade
- `0.20 < unknown ratio <= 0.40`: downgrade one level
- unknown ratio `> 0.40`: final confidence is at most `LOW`

An N/A base remains `UNKNOWN`; the unknown penalty cannot promote it to a
numeric confidence level. These thresholds are provisional and require later
calibration against representative real-device configurations. The current
posture-scoring eligibility gate consumes Analysis Confidence together with
the rule-assessment ratio; see [Security Posture Scoring V1](SCORING.md).

## Fixtures and limitations

The `coverage_*.cfg` samples are dedicated dirty coverage fixtures with
hand-asserted line counts. Existing security-rule golden samples are synthetic
and exercise known parser/rule paths; their high coverage does not represent
real-world configuration coverage for any platform.

Huawei S5720 / V200R021 first-slice real configurations may retain substantial
`UNSUPPORTED_RELEVANT` and `UNKNOWN_RELEVANCE` syntax. Broad allowlists are
intentionally avoided; unmodeled security families and unknown commands must
not inflate coverage. Resulting `LOW` Analysis Confidence describes limited
analyzer coverage, not low device security. See [Huawei VRP](HUAWEI_VRP.md).

Multi-line `banner motd` and `banner login` blocks are deliberately excluded
from V1 fixtures and classification allowlists. The current parser is
line-oriented and does not model free-text block delimiters or bodies. Banner
free text that coincidentally resembles a command family may therefore be
misclassified by the current line-oriented coverage classifier.

Coverage of vendor/platform/release defaults is a separate problem. An absent
command may have different effective meaning across Cisco versions, so V1
does not claim default-aware coverage. Representative real configurations and
known device profiles are required for both default-aware interpretation and
threshold calibration.

## Cisco discovery first slice

Exact global `cdp run` / `no cdp run`, `lldp run` / `no lldp run`, and
interface `cdp enable` / `no cdp enable`, `lldp transmit` / `no lldp transmit`
are parser-owned `SUPPORTED_RELEVANT` commands in their correct contexts.
Conflicting explicit commands leave the corresponding state `UNKNOWN`;
understanding command syntax does not establish effective enablement.

`lldp receive` / `no lldp receive` remain `UNSUPPORTED_RELEVANT`. Timers,
TLV controls, abbreviations and unverified resets are not normalized; unknown
variants remain `UNKNOWN_RELEVANCE`. No broad discovery allowlist is used.
Supported classification can change coverage/confidence for existing inputs;
classification formulas and thresholds are unchanged.
