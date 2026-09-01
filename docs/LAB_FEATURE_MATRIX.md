# Lab Validation Feature Matrix

Audit date: 2026-09-01. This is a feasibility audit, not a record of an
executed PoC. No image was downloaded and no traffic was generated.

`YES` means official material verifies the platform capability or the named
network feature on the explicitly identified image. `PARTIAL` means the
platform capability exists but the required feature depends on an image or has
material limitations. `UNVERIFIED` means no sufficiently specific official
statement was found. Platform support for an image is not treated as proof of
the image's network-feature support.

## Required feature matrix

| Requirement | Packet Tracer | GNS3 | EVE-NG | Containerlab |
|---|---|---|---|---|
| DHCP Snooping | **YES** — Cisco NetAcad has a Packet Tracer activity that configures global/VLAN snooping, trust, and rate limits; it warns that scoring may be imperfect [PT-1] | **PARTIAL** — IOSvL2 is usable as an appliance and Cisco verifies the feature on IOSvL2, but GNS3 supplies no Cisco image [GNS3-1][CML-1] | **PARTIAL** — vIOS L2/IOL images are supported, but feature behavior is image-dependent and EVE supplies no verified entitlement [EVE-1][CML-1] | **PARTIAL** — Cisco vIOS/IOL-L2 node kinds exist, but the user must lawfully provide and package the image [CLAB-1][CLAB-2] |
| Dynamic ARP Inspection | **UNVERIFIED** — no current official Packet Tracer document found that commits to functional DAI behavior | **PARTIAL** — Cisco lists DAI on IOSvL2, but lawful image availability is external to GNS3 [CML-1][GNS3-1] | **PARTIAL** — same IOSvL2 dependency; EVE support for the image is not feature certification [EVE-1][CML-1] | **PARTIAL** — vIOS L2 can be hosted, but Containerlab does not certify DAI behavior for the supplied image [CLAB-2][CML-1] |
| DHCP binding visibility | **UNVERIFIED** — DHCP Snooping configuration is documented, but binding-table fidelity is not | **PARTIAL** — expected from a supporting IOSvL2 image, but must be verified in the chosen build | **PARTIAL** — expected from a supporting IOSvL2 image, but must be verified in the chosen build | **PARTIAL** — expected from a supporting IOSvL2/IOL-L2 image, but must be verified in the chosen build |
| Interface trust/untrust | **YES** — the official activity explicitly configures trusted trunks and untrusted-port limits [PT-1] | **PARTIAL** — image-dependent; verified IOSvL2 DHCP Snooping is the viable candidate [CML-1] | **PARTIAL** — image-dependent | **PARTIAL** — image-dependent |
| BPDU Guard | **YES** — the official Packet Tracer activity explicitly configures PortFast and BPDU Guard [PT-1] | **UNVERIFIED** — GNS3 supports suitable L2 appliances, but no platform-specific official behavior proof was found | **UNVERIFIED** — no official EVE feature certification found for the candidate image | **UNVERIFIED** — no Containerlab feature certification found for the candidate image |
| Packet capture | **PARTIAL** — simulation/event inspection is available, but this audit found no official guarantee of ordinary downloadable PCAP parity | **YES** — official Web Wireshark documentation provides real-time link capture and inspection [GNS3-2] | **YES** — official documentation provides Wireshark capture; exact client/integrated workflow varies by edition [EVE-2] | **YES** — link capture is supported through Containerlab tooling/GUI [CLAB-3] |
| Config export | **PARTIAL** — projects are saved, but deterministic plain-text running-config extraction was not verified | **PARTIAL** — projects can be exported; running-config extraction depends on the appliance/workflow [GNS3-3] | **YES** — official export supports Cisco IOL and vIOS L2 configurations [EVE-3] | **YES** — Cisco IOL save and timestamped config copy are documented [CLAB-4] |
| Proprietary image required | **NO** — Cisco legally distributes Packet Tracer's simulated devices as part of the product | **YES** — GNS3 explicitly does not supply Cisco IOS images [GNS3-1] | **YES** — Cisco L2 images appear in the supported-image list, but must be supplied lawfully by the user [EVE-1] | **YES** — Cisco IOL/vIOS must be supplied and packaged by the user [CLAB-1][CLAB-2] |

## Platform comparison

| Platform | Linux/Fedora usability | Automation complexity | Reproducibility | Isolated defensive PoC suitability | Decision |
|---|---|---|---|---|---|
| Cisco Packet Tracer | Desktop Linux availability is plausible, but Fedora-specific current support was not verified | Low for manual labs; limited external automation | Medium; `.pkt` topology is portable, simulator fidelity is the constraint | DHCP Snooping and BPDU Guard only; DAI and binding fidelity are unverified | **NOT SUITABLE** for the selected two-PoC contract; useful teaching fallback |
| GNS3 | Linux server/client workflows are documented; Fedora-specific packaging was not verified | Medium | High if appliance version and lawful image digest are pinned | Technically promising with IOSvL2, but image rights and exact feature probe are prerequisites | **ALTERNATIVE**, conditional |
| EVE-NG | Linux client integration exists; EVE is normally deployed as its own VM/server | Medium | High if EVE version, template, and lawful image digest are pinned | Capture/export are strong; feature and image entitlement remain external | **ALTERNATIVE**, conditional |
| Containerlab | Strongest Fedora fit: official RPM/DNF guidance and Fedora Server testing [CLAB-5] | Medium-high because VM/container packaging is required | High with pinned topology and image digest | Excellent orchestration, but it cannot cure image licensing or unverified feature fidelity | **ALTERNATIVE**, conditional; not first choice |
| Cisco CML Personal + bundled IOSvL2 | Runs as a supported CML VM; browser access is OS-neutral, but Fedora as a VMware host is not explicitly certified [CML-2] | Low-medium | High with pinned CML/refplat versions and exported lab YAML | IOSvL2 officially lists DAI and DHCP Snooping; CML exports PCAP and running config [CML-1][CML-3][CML-4] | **RECOMMENDED**, subject to lawful CML Personal access |

## Feature and licensing conclusions

- Cisco documents IOSvL2 DHCP Snooping as tested and lists Dynamic ARP
  Inspection as supported. Cisco also documents that DAI depends on the DHCP
  Snooping binding database [CML-1][IOSXE-1].
- CML-Free is legally available and includes IOL-L2, but Cisco's CML-Free page
  does not establish that IOL-L2 implements the required DAI/binding behavior.
  It is therefore not substituted for IOSvL2 without a feature probe [CML-5].
- CML images are licensed for use within CML. They must not be extracted for
  GNS3, EVE-NG, or Containerlab unless the user has separate rights that
  explicitly permit that use [CML-5].
- GNS3 explicitly states that it cannot provide Cisco images. EVE-NG and
  Containerlab can host user-supplied Cisco images but do not establish the
  user's entitlement [GNS3-1][EVE-1][CLAB-1].
- No unofficial mirror, image-sharing workflow, license bypass, or extraction
  from CML is approved by this audit.

## Official sources

- **[PT-1]** Cisco Networking Academy, [Packet Tracer — Switch Security Configuration](https://contenthub.netacad.com/courses/srwe-bridge/_common/11.6.1-packet-tracer---switch-security-configuration.pdf).
- **[CML-1]** Cisco DevNet, [IOSvL2 supported and tested features](https://developer.cisco.com/docs/modeling-labs/2-5/iosvl2/).
- **[CML-2]** Cisco DevNet, [CML system requirements and supported virtualization](https://developer.cisco.com/docs/modeling-labs/system-requirements/).
- **[CML-3]** Cisco DevNet, [Downloading a packet capture](https://developer.cisco.com/docs/modeling-labs/2-6/downloading-a-packet-capture/).
- **[CML-4]** Cisco DevNet, [Extracting configurations](https://developer.cisco.com/docs/modeling-labs/extracting-configurations/).
- **[CML-5]** Cisco DevNet, [CML-Free images and licensing boundary](https://developer.cisco.com/docs/modeling-labs/cml-free/).
- **[IOSXE-1]** Cisco, [DAI and DHCP Snooping binding behavior](https://www.cisco.com/c/en/us/support/docs/switches/lan-switch-software/222274-troubleshoot-dynamic-arp-inspection-dai.html).
- **[GNS3-1]** GNS3, [Where do I get IOS images?](https://docs.gns3.com/docs/troubleshooting-faq/where-do-i-get-ios-images).
- **[GNS3-2]** GNS3, [Web Wireshark packet capture](https://docs.gns3.com/docs-3.1-en/web-ui/use-web-wireshark).
- **[GNS3-3]** GNS3, [Project topology import/export](https://docs.gns3.com/docs-3.1-en/web-ui/project-topology).
- **[EVE-1]** EVE-NG, [Supported images](https://www.eve-ng.net/index.php/documentation/supported-images/).
- **[EVE-2]** EVE-NG, [Client and Wireshark capture support](https://www.eve-ng.net/index.php/download/).
- **[EVE-3]** EVE-NG, [Initial configuration export](https://www.eve-ng.net/index.php/documentation/howtos-video/operate-with-eve-initial-configurations/).
- **[CLAB-1]** Containerlab, [Cisco IOL image requirements](https://containerlab.dev/manual/kinds/cisco_iol/).
- **[CLAB-2]** Containerlab, [Cisco vIOS/vIOSL2 kind](https://containerlab.dev/manual/kinds/cisco_vios/).
- **[CLAB-3]** Containerlab, [GUI packet capture](https://containerlab.dev/manual/gui/vsc-extension/).
- **[CLAB-4]** Containerlab, [Save and copy configurations](https://containerlab.dev/cmd/save/).
- **[CLAB-5]** Containerlab, [Linux and Fedora installation support](https://containerlab.dev/install/).
