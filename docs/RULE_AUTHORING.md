# Rule Authoring

## Safe configuration examples

`safe_config_example` is a minimal, context-aware remediation snippet. It
shows the parent configuration context required to apply the fix, such as
`interface <actual-interface>`, followed by only the commands needed to
address that finding.

A safe configuration example must not reproduce the complete interface or
device configuration. It must not invent unknown policy-specific values.

## Rule evaluation metadata

Every rule must expose detailed evaluation metadata in addition to its
backward-compatible `evaluate()` result.

Rules should implement:

```python
evaluate_detailed(config) -> RuleEvaluation
```

where:

```python
RuleEvaluation(
    findings=list[Finding],
    assessed_units=int,
)
```

`assessed_units` is the number of resources for which the rule's own
applicability, intent, and precondition requirements were sufficiently
satisfied to make a meaningful rule-level assessment.

It must be derived from the rule's existing candidate/precondition logic.
Do not duplicate the rule logic in a separate assessment service.

The assessment unit depends on the rule, for example:

- device
- VLAN
- interface
- VTY range

Important semantics:

- `assessed_units == 0` and no findings means the rule did not have enough
  applicability/context to make a meaningful assessment. It must not be
  interpreted as PASS.
- `assessed_units > 0` and no findings means no violation was observed within
  the scope actually assessed.
- `assessed_units > 0` with findings means the rule assessed applicable
  resources and found one or more violations.

`assessed_units` is not a cross-rule scoring unit. Counts from different rules
must not be added together because their resource units may differ.
