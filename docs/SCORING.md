# Security Posture Scoring V1

Security Posture Score summarizes violations found within the scope that the
current analyzer both understood and meaningfully assessed. It is not an
absolute claim that a device is secure.

The score is distinct from Analysis Confidence. Analysis Confidence describes
the completeness of parser understanding for the device. Finding Confidence
describes confidence in one finding and affects that finding's rule-level
penalty.

## Eligibility

All nine registered rules expose `RuleEvaluation`. V1 counts a rule as
assessed when its `assessed_units` is greater than zero:

```text
assessed_rule_count = count(evaluation.assessed_units > 0)
rule_assessment_ratio = assessed_rule_count / total_registered_rules
```

This ratio is a provisional rule-level assessment completeness signal. It is
not full Control Assessment Coverage: rules use different units such as a
device, VLAN, interface, or VTY range.

A score is available only when:

```text
Analysis Confidence is HIGH or MEDIUM
and rule_assessment_ratio >= 0.60
```

Analysis Confidence `LOW` or `UNKNOWN`, or an assessment ratio below `0.60`,
makes score and risk level N/A. Parser Coverage is not applied as a second
gate because Analysis Confidence already incorporates parser coverage and its
unknown-line penalty.

This resolves the zero-finding collision for scoring eligibility:

- no findings with zero assessed rules does not produce 100;
- no findings with sufficient assessment may produce 100.

A score of 100 means no violation was observed in the sufficiently assessed,
supported scope. It does not mean the device is universally secure.

## Finding penalty

Severity weights are:

| Severity | Weight |
|---|---:|
| HIGH | 15 |
| MEDIUM | 8 |
| LOW | 4 |

Finding Confidence multipliers are:

| Finding Confidence | Multiplier |
|---|---:|
| HIGH | 1.00 |
| MEDIUM | 0.70 |
| LOW | 0.40 |

```text
base_penalty = severity_weight * finding_confidence_multiplier
```

Findings under the same rule ID receive one rule-level base penalty, not one
base penalty per finding.

## Exposure normalization

For each rule ID:

```text
observed_units = max(
    finding_count,
    unique_affected_interface_count,
)

violating_units = min(
    evaluation.assessed_units,
    observed_units,
)

factor = min(
    1.60,
    1 + 0.15 * log2(max(1, violating_units)),
)

rule_penalty = base_penalty * factor
```

This gives exposure a capped diminishing return instead of multiplying a
penalty linearly by finding count. Capping by `assessed_units` also preserves
the rule's aggregation unit. For example, one DAI VLAN assessment remains one
violating VLAN even if its finding lists many affected interfaces, while an
STP rule that assessed many interfaces can represent broader exposure.

A finding with zero assessed units is an invariant violation and is rejected
as a scoring input.

## Overlap policy

The current catalogue has no reliably established `CLEAR_OVERLAP` pair. V1
therefore performs no overlap deduplication, correlation grouping, category
multiplier, or `POSSIBLE_OVERLAP` suppression. Different rules continue to
produce independent rule-level penalties.

## Score and risk bands

```text
total_penalty = sum(rule_penalties)
raw_score = max(0.0, 100.0 - total_penalty)
display_score = round(raw_score)
```

Risk level uses the internal raw score. `display_score` is presentation-only,
so rounding cannot move a device across a risk boundary:

| Raw score | Risk level |
|---:|---|
| 90–100 | LOW |
| 75–<90 | MODERATE |
| 50–<75 | HIGH |
| 0–<50 | CRITICAL |

All weights, caps, eligibility thresholds, and risk bands are provisional.
They require calibration using representative real configurations and worked
multi-finding scenarios before being treated as operational policy.
