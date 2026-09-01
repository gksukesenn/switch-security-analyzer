# ADR-005: Defensive Lab Validation Platform

- Status: Accepted with acquisition precondition
- Date: 2026-09-01

## Context

The analyzer needs validation against configurations exported from a real
emulated switch, beyond synthetic golden fixtures. The first two defensive
contracts cover rogue DHCP mitigation with DHCP Snooping and invalid ARP
mitigation with Dynamic ARP Inspection (DAI). The lab must remain isolated and
must provide observable traffic behavior, switch state, and reproducible
configuration export without unlawful image acquisition.

## Required features

- Functional DHCP Snooping with VLAN scope and interface trust/untrust.
- Visible DHCP Snooping bindings.
- Functional DAI using the DHCP binding context.
- Link-level packet capture or equivalent deterministic observation.
- Exportable running configuration suitable for analyzer input.
- A lawful, reproducible image source.
- BPDU Guard as a fallback candidate.

## Options considered

- Cisco Packet Tracer.
- GNS3 with a user-supplied Cisco L2 image.
- EVE-NG with a user-supplied Cisco L2 image.
- Containerlab with a user-supplied and packaged Cisco L2 image.
- Cisco Modeling Labs (CML) Personal with its bundled IOSvL2 reference image.

The detailed evidence and per-feature ratings are in
`docs/LAB_FEATURE_MATRIX.md`.

## Decision

**RECOMMENDED:** Cisco CML Personal with the bundled, version-pinned IOSvL2
reference platform, operated as a completely isolated lab.

Cisco officially lists DHCP Snooping and DAI as IOSvL2 features and tests DHCP
Snooping in CML. CML also provides downloadable PCAP and running-configuration
extraction. The platform therefore provides the shortest documented path to
both primary PoCs and to analyzer validation using exported Cisco-style config.

Execution is conditional on the user obtaining lawful CML Personal access and
using the bundled image only within CML. Before any PoC, a non-adversarial
feature gate must record the exact CML/refplat/IOSvL2 versions and confirm that
the documented show-state exposes DHCP bindings and DAI counters on that build.

**ALTERNATIVE:** GNS3, EVE-NG, or Containerlab may be selected only if the user
already has a Cisco L2 image with explicit rights for use on that platform and
a harmless feature probe confirms DHCP Snooping, DAI, binding visibility, and
config export. Containerlab has the best native Fedora story; GNS3 and EVE-NG
have mature GUI capture workflows.

**NOT SUITABLE for both primary PoCs:** Packet Tracer. Cisco documents DHCP
Snooping and BPDU Guard activities, but this audit could not verify DAI and
binding-table fidelity from current official material. It remains a possible
fallback teaching environment, not the acceptance platform.

## Trade-offs

- CML Personal introduces acquisition cost and VM resource requirements.
- IOSvL2 is performance-limited, but throughput is not material to these small,
  deterministic control validations.
- CML-Free is no-cost and includes IOL-L2, but the required DAI/binding feature
  set was not verified for that image during this audit.
- Containerlab offers stronger topology-as-code automation on Fedora, while
  adding image packaging complexity and no independent feature guarantee.
- GNS3/EVE-NG can be reproducible once an image is pinned, but the platform
  cannot supply or legalize the Cisco image.

## Licensing and image constraints

- Do not download from unofficial mirrors, share images, bypass licenses, or
  extract CML reference images for another platform.
- CML-provided Cisco images are restricted to use within CML unless separate
  rights explicitly say otherwise.
- GNS3, EVE-NG, and Containerlab are viable only with an already-lawful image
  whose terms allow use there.
- Record the platform version, image filename/version, and cryptographic digest
  in the eventual evidence manifest; do not commit the image to this repo.

## Rejected alternatives

- Packet Tracer for the paired DHCP Snooping + DAI acceptance: DAI/binding
  behavior remains unverified.
- GNS3/EVE-NG/Containerlab with images sourced from community mirrors: rejected
  on licensing and provenance grounds.
- Physical or production infrastructure: outside this phase and unnecessary
  for feasibility planning.
- CML-Free IOL-L2 as an assumed drop-in replacement: rejected until the exact
  required feature behavior is harmlessly verified.
