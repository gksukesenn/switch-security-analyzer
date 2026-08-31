# Multi-vendor direction

- Detection logic remains on the normalized model.
- Each vendor parser produces normalized field evidence as `SourceLine`
  provenance alongside the normalized value.
- Rules must not scan raw vendor command syntax when normalized provenance is
  available.
- Safe-configuration syntax is delegated to a vendor renderer. The Cisco
  renderer is the current reference implementation and preserves the existing
  output exactly.
- If a renderer is unavailable, safe configuration is `N/A`; Cisco syntax is
  never used as a cross-vendor fallback.
- An Aruba renderer is planned for the next vendor checkpoint. New vendor
  orchestration must explicitly select a parser and renderer without adding
  vendor branches to rules.

The first Aruba vertical slice may produce `score=N/A` because the current
nine-rule denominator may not satisfy the assessment gate. This is expected at
that stage and is not a permanent Aruba characteristic. The assessment gate can
be crossed as more verified Aruba rules are added.
