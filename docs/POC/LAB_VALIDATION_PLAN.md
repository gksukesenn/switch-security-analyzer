# Defensive Lab Validation Plan

Status: plan only. No PoC traffic has been generated. All future execution is
restricted to an isolated, synthetic lab with no production or customer data.

## Preconditions and common controls

- Use Cisco CML Personal with its lawfully bundled, pinned IOSvL2 image, or an
  ADR-approved alternative with documented image entitlement.
- Keep every data-plane link inside the lab. Do not bridge the test VLAN to a
  production, corporate, home, or Internet-facing network.
- Use only synthetic hostnames, VLANs, addresses, and endpoint identities.
- Record platform, image, topology, and analyzer commit identifiers before the
  test. Preserve the same topology and controlled stimulus for before/after
  comparison.
- First perform a non-adversarial feature gate: confirm config acceptance,
  binding visibility, DAI status/counters, capture availability, and config
  extraction. A missing capability blocks the related PoC.

## PoC-1: Rogue DHCP behavior versus DHCP Snooping

Threat class: rogue DHCP / DHCP spoofing. Analyzer scope: `DHCP-001`,
`DHCP-002`, and `DHCP-003`.

### Defensive validation contract

1. **Weak configuration state:** In an isolated endpoint VLAN, preserve a
   deterministic DHCP Snooping defect recognized by one relevant analyzer
   rule—for example, intended VLAN scope exists while global enforcement is
   inactive. Export the real lab switch configuration.
2. **Expected controlled lab symptom:** During a bounded lab-only control test,
   an unauthorized DHCP response is accepted or is observably not filtered at
   the intended trust boundary.
3. **Analyzer expectation:** Analyze the exported weak configuration with the
   existing Cisco pipeline. The corresponding DHCP finding is present with
   evidence tied to the exported configuration.
4. **Defensive change:** Correct global/VLAN DHCP Snooping coverage and the
   authorized-server trust boundary, without broadening trust to endpoint
   ports.
5. **Repeat:** Export the remediated config, rerun the analyzer, and repeat the
   identical bounded control test.
6. **Expected defensive evidence:** The relevant analyzer finding disappears;
   the legitimate DHCP path remains functional; the same unauthorized response
   is filtered; switch status/counters and the observation record agree.

No packet-crafting or offensive command sequence is specified by this plan.

### Acceptance evidence

- `poc1/config-before.txt`: exported switch configuration.
- `poc1/analyzer-before.json`: analyzer output with relevant DHCP finding.
- `poc1/switch-state-before.txt`: DHCP Snooping status, VLAN/trust state, and
  binding visibility.
- `poc1/observation-before.*`: PCAP or platform observation showing the weak
  behavior, with sensitive or irrelevant payload excluded.
- `poc1/config-after.txt`: exported remediated configuration.
- `poc1/analyzer-after.json`: analyzer output showing the expected finding
  transition.
- `poc1/switch-state-after.txt`: enforcement status, bindings, and relevant
  counters.
- `poc1/observation-after.*`: defensive retest evidence showing filtering.

## PoC-2: Invalid ARP behavior versus Dynamic ARP Inspection

Threat class: ARP spoofing / poisoning. Analyzer scope: `DAI-001`. Dependency:
a valid DHCP Snooping binding context.

### Defensive validation contract

1. **Weak configuration state:** Establish a legitimate DHCP lease and visible
   binding on a DHCP Snooping-protected endpoint VLAN, while DAI is absent for
   that VLAN. Export the real lab switch configuration.
2. **Expected controlled lab symptom:** In a bounded lab-only ARP-validation
   test, invalid ARP behavior is observable because the switch is not applying
   DAI validation on that VLAN.
3. **Analyzer expectation:** The exported weak configuration produces
   `DAI-001`, with the relevant VLAN and endpoint evidence.
4. **Defensive change:** Enable DAI for the protected VLAN while retaining the
   valid DHCP Snooping binding and correct trust boundary.
5. **Repeat:** Export and analyze the remediated config, then repeat the exact
   same controlled validation.
6. **Expected defensive evidence:** `DAI-001` disappears, the invalid ARP
   behavior is rejected, valid bound-host traffic remains functional, and DAI
   status/drop evidence corroborates the result.

Static-address hosts and ARP ACL exceptions are excluded from V1. No packet-
crafting or exploit sequence is specified.

### Acceptance evidence

- `poc2/config-before.txt` and `poc2/analyzer-before.json`.
- `poc2/dhcp-bindings-before.txt`: valid binding context.
- `poc2/dai-state-before.txt`: DAI absent/inactive state.
- `poc2/observation-before.*`: bounded invalid-ARP observation.
- `poc2/config-after.txt` and `poc2/analyzer-after.json`.
- `poc2/dhcp-bindings-after.txt`: binding remains valid.
- `poc2/dai-state-after.txt`: enabled VLAN/trust state and relevant counters.
- `poc2/observation-after.*`: rejection plus legitimate-connectivity evidence.

## Fallback: STP edge protection

Use this only if either primary feature fails its harmless platform gate.

1. Export a synthetic access-interface config with PortFast/admin-edge intent
   and without effective BPDU Guard.
2. Confirm `STP-001` in analyzer output.
3. In the isolated lab, observe at a high level that unexpected edge BPDUs are
   not protected by the intended guard policy.
4. Enable BPDU Guard, export the config, and confirm the finding disappears.
5. Repeat the same controlled observation and record the expected protected
   interface behavior and switch event/status evidence.

Packet Tracer officially documents PortFast/BPDU Guard configuration and may
serve as a teaching fallback. Acceptance against an emulator still requires a
platform/image-specific behavior gate.

## Evidence integrity and result recording

Create a manifest containing SHA-256 hashes for every text export and capture,
the analyzer commit, platform/refplat/image versions, topology identifier, UTC
timestamps, and the operator's pass/fail notes. Keep raw proprietary images and
any licensed platform artifacts outside the repository. A PoC passes only when
both the network-defense transition and analyzer finding transition match the
contract; a missing or ambiguous observation is `INCONCLUSIVE`, not `PASS`.
