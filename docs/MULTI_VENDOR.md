# Multi-vendor direction

- Vendor selection is explicit. An omitted vendor defaults to `cisco_ios` only
  for backward compatibility; configuration syntax is not auto-detected.
- The parser, safe-configuration renderer, and coverage registry are selected
  together at application composition time.
- `aruba_aos_cx` selects the Aruba parser, renderer, and coverage registry.
  Unsupported vendors fail explicitly and never fall back to Cisco components.

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
- The Aruba renderer implements the verified first-slice operations and returns
  `N/A` for unsupported operations. New vendor orchestration must explicitly
  select a parser and renderer without adding vendor branches to rules.

Aruba scoring uses the unchanged nine-rule denominator and assessment gate. A
partial configuration may produce `score=N/A`; the fully safe first-slice
fixture naturally reaches five assessed rules, so its 5/9 assessment ratio
produces `score=N/A`. This does not imply a worse security result; it reflects
that four controls are not yet assessed. See `ARUBA_AOS_CX.md` for the current
scope.
