# REST API V1

The REST API exposes Cisco IOS and the Aruba AOS-CX first-slice pipelines. The API layer
orchestrates parsing, registered rule evaluation, parser coverage, Analysis
Confidence, and posture scoring; it does not implement security or scoring
logic itself.

## Running locally

Install the pinned development dependencies into a virtual environment, then
start the ASGI application with the installed Uvicorn module:

```bash
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```

## `GET /health`

This deterministic endpoint has no external dependency checks.

```json
{
  "status": "ok"
}
```

## `POST /analyze`

Request body:

```json
{
  "vendor": "cisco_ios",
  "config": "hostname ACCESS-SW-01\nip http server\n"
}
```

`config` is required, must be a string, and must not be empty or contain only
whitespace. Its UTF-8 representation is limited to 1 MiB (1,048,576 bytes).
`vendor` is optional and defaults to `cisco_ios` for backward compatibility.
Vendor auto-detection is not performed.

Example:

```bash
curl --request POST http://127.0.0.1:8000/analyze \
  --header 'content-type: application/json' \
  --data '{"vendor":"cisco_ios","config":"hostname ACCESS-SW-01\nip http server\n"}'
```

The response has four sections:

```json
{
  "device": {
    "vendor": "cisco_ios",
    "hostname": "ACCESS-SW-01"
  },
  "analysis": {
    "parser_coverage": 1.0,
    "unknown_ratio": 0.0,
    "analysis_confidence": "high",
    "assessed_rule_count": 1,
    "total_rule_count": 9,
    "rule_assessment_ratio": 0.1111111111111111
  },
  "posture": {
    "score": null,
    "display_score": null,
    "risk_level": null,
    "total_penalty": null,
    "unavailable_reason": "insufficient_rule_assessment",
    "rule_penalties": []
  },
  "findings": [
    {
      "rule_id": "MGMT-002",
      "title": "Insecure HTTP management service explicitly enabled",
      "category": "MGMT",
      "severity": "high",
      "confidence": "high",
      "technical_impact": "...",
      "remediation": "...",
      "safe_config_example": "no ip http server",
      "affected_interfaces": [],
      "evidence": [
        {
          "line_number": 2,
          "text": "ip http server"
        }
      ]
    }
  ]
}
```

Finding and evidence order follows the deterministic registered-rule and
rule-evidence order. When scoring is eligible, `rule_penalties` contains the
existing scoring model's rule-level base penalty, exposure factor, violating
units, and final penalty.

## N/A posture

Unavailable posture values are JSON `null`, never numeric zero. This keeps an
unavailable score distinct from a real score of zero. `unavailable_reason`
reports the existing scoring gate reason, such as insufficient rule
assessment or low/unknown Analysis Confidence.

Parser Coverage may also be `null` when no supported or known unsupported
relevant syntax is present.

## Validation and errors

- Missing fields, wrong types, blank config, and malformed JSON return `422`.
- Unknown vendors return `422`. Supported explicit identifiers are `cisco_ios`
  and `aruba_aos_cx`; neither ever falls back to the other vendor's pipeline.
- Config input larger than 1 MiB returns `413`.
- Unexpected internal failures return `500` with a generic response and no
  Python traceback or internal exception detail.

## V1 scope and limitations

The reference implementation analyzes Cisco IOS/IOS-XE syntax and a documented
Aruba AOS-CX 10.12/10.13 first-slice subset. Parser,
safe-config renderer, and coverage registry are selected together from the
explicit vendor identifier. V1
does not provide authentication, production hardening, rate limiting, TLS
termination, persistent storage, background processing, file upload, batch
analysis, or a frontend. Vendor auto-detection and cross-vendor fallback are
not provided.

Deployments must add authentication, transport security, request controls,
and other operational protections outside this V1 application before any
production exposure.
