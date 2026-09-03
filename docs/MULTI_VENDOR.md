# Multi-platform architecture

- Vendor selection is explicit. An omitted vendor defaults to `cisco_ios` only
  for backward compatibility; configuration syntax is not auto-detected.
- The parser, safe-configuration renderer, and coverage registry are selected
  together at application composition time.
- Each identifier selects one complete component set:
  - `cisco_ios`: Cisco IOS/IOS-XE;
  - `aruba_aos_cx`: Aruba AOS-CX; and
  - `aruba_aos_s`: ArubaOS-Switch / AOS-S.
- A brand is not a network operating system. AOS-CX and AOS-S therefore use
  separate parsers, renderers, and coverage registries despite both being
  Aruba platforms.
- Unsupported vendors fail explicitly and never fall back to Cisco, AOS-CX,
  or AOS-S components.

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
- Each Aruba renderer implements only its verified first-slice operations and
  returns `N/A` for unsupported operations. Platform orchestration explicitly
  selects components without adding vendor branches to rules.

AOS-CX can assess up to five existing rules in its first slice; AOS-S can
assess up to four where the required static evidence exists. Both use the
unchanged nine-rule denominator and assessment gate, so limited platform
slices may naturally produce `score=N/A`. This reports incomplete assessment,
not a worse security result. See [AOS-CX scope](ARUBA_AOS_CX.md),
[AOS-S scope](ARUBA_AOS_S.md), and [Scoring](SCORING.md).

Batch Analysis can select any of the three platform pipelines within one
request. Each
device's explicit vendor is passed through the same single-device application
service, and batch logic only aggregates the returned results. It does not
auto-detect vendors or combine vendor scoring semantics.
