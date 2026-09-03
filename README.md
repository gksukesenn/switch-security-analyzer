# Switch Security Analyzer

Switch Security Analyzer performs deterministic static analysis of switch
configuration text. It parses supported security state, evaluates the current
nine-rule catalogue, reports findings with evidence and remediation, measures
analysis completeness, and produces a scoped posture score when eligibility
requirements are met. It is an analysis aid, not a security certification or
a production-grade vulnerability scanner.

## Supported platforms

- Cisco IOS / IOS-XE: the primary supported parser and rule pipeline. Coverage
  is deliberately limited to the documented command families.
- Aruba AOS-CX 10.12/10.13: a partial first slice covering DHCPv4 Snooping,
  Dynamic ARP Inspection, access-interface state, administrative edge intent,
  and BPDU Guard.

The caller selects `cisco_ios` or `aruba_aos_cx` explicitly. The application
does not auto-detect vendors. See [Multi-vendor direction](docs/MULTI_VENDOR.md)
and [Aruba scope](docs/ARUBA_AOS_CX.md).

## Rule catalogue

| Rule | Current check |
|---|---|
| `DHCP-001` | DHCP Snooping globally inactive |
| `DHCP-002` | Access VLAN not covered by DHCP Snooping |
| `DHCP-003` | DHCP Snooping trusted on an access port |
| `DAI-001` | DHCP Snooping-protected VLAN lacks DAI coverage |
| `IPSG-001` | DHCP endpoint lacks IP Source Guard |
| `PORTSEC-001` | Inconsistent Port Security within an access VLAN |
| `STP-001` | PortFast edge port lacks effective BPDU Guard |
| `MGMT-001` | VTY lines explicitly permit Telnet |
| `MGMT-002` | Standard HTTP management server explicitly enabled |

Not every rule is supported for every vendor. Aruba's exact first-slice rule
set is documented in [Aruba AOS-CX V1 scope](docs/ARUBA_AOS_CX.md).

## Result concepts

- **Finding Severity** represents the impact of a reported condition.
- **Finding Confidence** represents confidence in that individual finding and
  contributes to its scoring penalty.
- **Parser Coverage** measures how much declared analysis-relevant syntax was
  understood; it is not a security score.
- **Analysis Confidence** is device-level confidence in analysis completeness.
- **RuleEvaluation / assessed_units** records how many applicable resources a
  rule could meaningfully assess. Zero assessed units is not a pass.
- **Security Posture Score** summarizes findings only inside sufficiently
  assessed supported scope. It is not an absolute statement of security.

A posture score is N/A when the scoring eligibility gate is not met. API N/A
values are JSON `null`, never numeric zero. This commonly occurs for the Aruba
partial slice because its five assessed rules do not meet the unchanged 60%
nine-rule gate. See [Scoring](docs/SCORING.md) and
[Parser Coverage](docs/PARSER_COVERAGE.md).

## Local setup

Python 3.10 or newer is required. Runtime dependencies and development/test
dependencies are intentionally separated:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Start the API:

```bash
python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```

Check it:

```bash
curl --fail http://127.0.0.1:8000/health
```

Analyze one Cisco sample with the CLI:

```bash
python -m src.cli samples/cisco/mgmt_002_http_enabled.cfg
```

The CLI is the existing Cisco single-config interface. Multi-vendor analysis
is exposed through the API.

## API

Single-device analysis:

```bash
curl --fail --request POST http://127.0.0.1:8000/analyze \
  --header 'content-type: application/json' \
  --data '{"vendor":"cisco_ios","config":"hostname ACCESS-SW-01\nip http server\n"}'
```

File upload analysis:

```bash
curl --fail --request POST http://127.0.0.1:8000/analyze/file \
  --form 'vendor=cisco_ios' \
  --form 'file=@switch.cfg;type=text/plain'
```

Mixed batch analysis:

```bash
curl --fail --request POST http://127.0.0.1:8000/analyze/batch \
  --header 'content-type: application/json' \
  --data '{"devices":[{"device_id":"cisco-01","vendor":"cisco_ios","config":"ip http server\n"},{"device_id":"aruba-01","vendor":"aruba_aos_cx","config":"interface 1/1/1\n no routing\n vlan access 20\n spanning-tree port-type admin-edge\n"}]}'
```

The API limits each UTF-8 configuration to 1 MiB and each batch to 50 devices.
See the complete [API contract](docs/API.md) and
[batch behavior](docs/BATCH_ANALYSIS.md).

## Docker

Build and run the stateless API as a non-root container:

```bash
docker build --tag switch-security-analyzer:local .
docker run --rm --name switch-security-analyzer \
  --publish 127.0.0.1:8000:8000 \
  switch-security-analyzer:local
```

Or use the single-service Compose definition:

```bash
docker compose up --build
```

The image contains only the API application and runtime dependencies. It does
not package CML, switch images, VM artefacts, lab tooling, tests, or secrets.

## Tests and demonstration

```bash
source .venv/bin/activate
python -m pytest -q
```

For a short, deterministic health, Cisco, Aruba, scoring, batch, and evidence
walkthrough, follow [Final demonstration](docs/DEMO.md). Release verification
is tracked in [Release checklist](docs/RELEASE_CHECKLIST.md).

## Current limitations

- Cisco support is scoped, line-oriented, and not a complete IOS/IOS-XE model.
- Aruba support is only the documented partial first slice.
- Vendor/platform/release defaults are not inferred unless explicitly modeled.
- There is no authentication, TLS termination, rate limiting, aggregate HTTP
  body cap, persistent storage, frontend, or vendor auto-detection.
- Production exposure requires external authentication, transport security,
  deployment-level request controls, logging, and operational monitoring.

See [Known limitations](docs/KNOWN_LIMITATIONS.md) for rule-specific details.

## Defensive lab validation status

- STP / BPDU Guard: **VALIDATED**
- Port Security: **VALIDATED**
- DHCP Snooping: **NOT VALIDATED / INVESTIGATION**

The DHCP experiment is not a successful validation, and its setup-specific
result is not evidence that the platform generally lacks support. Recorded
evidence is under [docs/POC](docs/POC/).
