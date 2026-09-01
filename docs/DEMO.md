# Deterministic Final Demonstration

This sequence uses committed configuration samples and the existing API
contract. Start the service locally or with Docker, then run the commands from
the repository root.

```bash
export ANALYZER_URL=http://127.0.0.1:8000
```

## 1. Health

```bash
curl --fail "$ANALYZER_URL/health"
```

Expected: HTTP 200 and `{"status":"ok"}`.

## 2. Cisco finding and safe counterpart

```bash
curl --fail --request POST "$ANALYZER_URL/analyze" \
  --header 'content-type: application/json' \
  --data "$(python -c 'import json; from pathlib import Path; print(json.dumps({"vendor":"cisco_ios","config":Path("samples/cisco/mgmt_002_http_enabled.cfg").read_text()}))')"
```

Expected: `MGMT-002` with `high` severity and `high` confidence, matching the
lowercase JSON enum values in the API response.

Repeat with the safe counterpart:

```bash
curl --fail --request POST "$ANALYZER_URL/analyze" \
  --header 'content-type: application/json' \
  --data "$(python -c 'import json; from pathlib import Path; print(json.dumps({"vendor":"cisco_ios","config":Path("samples/cisco/mgmt_002_http_disabled.cfg").read_text()}))')"
```

Expected: an empty `findings` list.

## 3. Scored Cisco result

```bash
curl --fail --request POST "$ANALYZER_URL/analyze" \
  --header 'content-type: application/json' \
  --data "$(python -c 'import json; from pathlib import Path; print(json.dumps({"vendor":"cisco_ios","config":Path("samples/demo/cisco_scored_safe.cfg").read_text()}))')"
```

Expected: nine assessed rules, no findings, score `100.0`, and risk `low`.
This means no violation was observed in fully assessed supported scope; it is
not an absolute security certification.

## 4. Aruba routing and N/A scoring

```bash
curl --fail --request POST "$ANALYZER_URL/analyze" \
  --header 'content-type: application/json' \
  --data "$(python -c 'import json; from pathlib import Path; print(json.dumps({"vendor":"aruba_aos_cx","config":Path("samples/aruba/coverage_supported_only.cfg").read_text()}))')"
```

Expected: vendor `aruba_aos_cx`, five assessed rules, no findings, and posture
score `null` because the partial Aruba slice does not meet the unchanged
nine-rule assessment gate.

## 5. Mixed batch

```bash
curl --fail --request POST "$ANALYZER_URL/analyze/batch" \
  --header 'content-type: application/json' \
  --data "$(python -c 'import json; from pathlib import Path; print(json.dumps({"devices":[{"device_id":"cisco-01","vendor":"cisco_ios","config":Path("samples/demo/cisco_scored_safe.cfg").read_text()},{"device_id":"aruba-01","vendor":"aruba_aos_cx","config":Path("samples/aruba/stp_001_admin_edge_without_bpdu_guard.cfg").read_text()}]}))')"
```

Expected: two devices in request order, one scored Cisco device, one unscored
Aruba device, and aggregate statistics showing one `STP` finding.

## 6. Recorded defensive validation

Do not recreate the switch lab during the normal demo. Show the preserved
records instead:

- [STP / BPDU Guard validation](POC/STP_BPDU_GUARD_VALIDATION.md): validated
  transition from `STP-001` to no findings and BPDU-triggered err-disable.
- [Port Security validation](POC/PORT_SECURITY_VALIDATION.md): validated
  transition from `PORTSEC-001` to no findings and controlled second-MAC
  secure-shutdown.
- DHCP Snooping remains **NOT VALIDATED / INVESTIGATION**. The attempted result
  is not a successful validation and does not establish a general platform
  limitation.
