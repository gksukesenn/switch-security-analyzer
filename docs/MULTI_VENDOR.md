# Multi-vendor direction

- Detection logic remains on the normalized model.
- Each vendor parser produces normalized field evidence as `SourceLine`
  provenance alongside the normalized value.
- Rules must not scan raw vendor command syntax when normalized provenance is
  available.
- Vendor-specific safe configuration rendering will be addressed in a separate
  vendor-adapter checkpoint. Safe examples remain Cisco-specific for now.
- The Aruba parser will not be implemented until the normalized-evidence
  refactor is complete.

The first Aruba vertical slice may produce `score=N/A` because the current
nine-rule denominator may not satisfy the assessment gate. This is expected at
that stage and is not a permanent Aruba characteristic. The assessment gate can
be crossed as more verified Aruba rules are added.
