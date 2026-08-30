# Rule Authoring

## Safe configuration examples

`safe_config_example` is a minimal, context-aware remediation snippet. It
shows the parent configuration context required to apply the fix, such as
`interface <actual-interface>`, followed by only the commands needed to
address that finding.

A safe configuration example must not reproduce the complete interface or
device configuration. It must not invent unknown policy-specific values.
