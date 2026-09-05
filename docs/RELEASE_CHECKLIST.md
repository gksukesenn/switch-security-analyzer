# Final Release Checklist

Run this checklist from a clean checkout before creating a release commit or
tag. Do not commit generated response files or container artefacts.

## Reproducibility and quality

- [ ] Working tree is clean before release verification.
- [ ] `python -m pip install -r requirements-dev.txt` succeeds in a fresh
  virtual environment.
- [ ] `python -m pytest -q` reports the complete passing suite.
- [ ] `git diff --check` reports no whitespace errors.
- [ ] CLI smoke test succeeds with a committed Cisco sample.
- [ ] API `GET /health` returns HTTP 200 and `{"status":"ok"}`.
- [ ] Cisco `POST /analyze` smoke test matches the API schema.
- [ ] Separate Aruba AOS-CX and AOS-S `POST /analyze` smoke tests match the API
  schema and preserve N/A posture as JSON `null` where applicable.
- [ ] Huawei VRP `POST /analyze` preserves `huawei_vrp` and permits N/A posture.
- [ ] Mixed Cisco/Aruba/Huawei `POST /analyze/batch` preserves per-device order and
  reports deterministic aggregate statistics.

## Container

- [ ] `docker build --tag switch-security-analyzer:release-check .` succeeds.
- [ ] The image starts without reload/debug mode and listens on container port
  8000 at `0.0.0.0`.
- [ ] The running process is non-root.
- [ ] Container health, Cisco, Aruba AOS-CX, Aruba AOS-S, Huawei, and
  mixed-batch smoke tests pass.
- [ ] `docker compose config` validates the single stateless service.

## Scope and handoff

- [ ] README and detailed docs agree with implemented API, parser coverage,
  scoring, vendor, and rule-authoring contracts.
- [ ] STP / BPDU Guard PoC is documented as **VALIDATED**.
- [ ] Port Security PoC is documented as **VALIDATED**.
- [ ] DHCP Snooping is documented only as **NOT VALIDATED / INVESTIGATION**,
  without a general platform-support claim.
- [ ] No secrets, `.env` files, proprietary images, CML/VM artefacts, captures,
  or other large generated files are tracked.
- [ ] No uncommitted generated files remain.
- [ ] No new rule, vendor, Aruba scope, scoring semantics, or unrelated
  architecture change was introduced.
- [ ] Protected semantic diffs are empty:

  ```bash
  git diff -- src/rules
  git diff -- src/parsers
  git diff -- src/domain
  git diff -- src/services/scoring.py
  ```
