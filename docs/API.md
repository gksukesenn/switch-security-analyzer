# REST API V1

The REST API exposes the Cisco IOS/IOS-XE, Aruba AOS-CX, and ArubaOS-Switch
first-slice pipelines. The API layer orchestrates parsing, registered rule
evaluation, parser coverage, Analysis Confidence, and posture scoring; it does
not implement security or scoring logic itself.

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
Vendor auto-detection is not performed. Supported explicit values are
`cisco_ios`, `aruba_aos_cx`, and `aruba_aos_s`.

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

## `POST /analyze/file`

The file endpoint accepts `multipart/form-data` with a required `file` upload
and an explicit `vendor` field. It reads the upload in memory as strict UTF-8
text and sends it through the same single-device analysis pipeline as
`POST /analyze`; its response schema is identical.

```bash
curl --request POST http://127.0.0.1:8000/analyze/file \
  --form 'vendor=cisco_ios' \
  --form 'file=@switch.cfg;type=text/plain'
```

The uploaded content must be non-blank and no larger than 1 MiB. The filename
and media type are treated as untrusted metadata: they neither select the
vendor nor determine whether the content is accepted. Uploaded configurations
are not persisted.

## `POST /analyze/batch`

The batch endpoint analyzes between 1 and 50 explicitly identified devices.
Each device requires a unique, non-empty `device_id`, an explicit supported
`vendor`, and a non-blank `config`:

```json
{
  "devices": [
    {
      "device_id": "cisco-01",
      "vendor": "cisco_ios",
      "config": "hostname CISCO-01\nip http server\n"
    },
    {
      "device_id": "aruba-01",
      "vendor": "aruba_aos_cx",
      "config": "hostname ARUBA-01\ndhcpv4-snooping\n"
    }
  ]
}
```

V1 processes devices sequentially in request order through the same
single-device pipeline used by `POST /analyze`. Device entries contain
`device_id` plus the complete single-device `device`, `analysis`, `posture`,
and `findings` sections. The response adds:

```json
{
  "statistics": {
    "total_devices": 2,
    "total_findings": 3,
    "scored_devices": 1,
    "unscored_devices": 1,
    "by_vendor": {
      "cisco_ios": {
        "device_count": 1,
        "finding_count": 1,
        "scored_device_count": 1,
        "unscored_device_count": 0
      },
      "aruba_aos_cx": {
        "device_count": 1,
        "finding_count": 2,
        "scored_device_count": 0,
        "unscored_device_count": 1
      }
    },
    "by_category": {
      "DHCP_SPOOFING": 1,
      "MGMT": 1,
      "STP": 1
    }
  }
}
```

Unavailable device scores and risk levels remain JSON `null`; they increment
unscored counts and are never converted to zero. No average score or risk is
reported.

An empty batch, more than 50 devices, duplicate IDs, missing or blank values,
and invalid vendors reject the whole request with `422`. Each config retains
the existing 1 MiB UTF-8 limit; an oversized config returns `413`. V1 adds no
separate total-request byte budget. It has no partial-success response, and an
unexpected failure returns the same generic `500` as single-device analysis.

## N/A posture

Unavailable posture values are JSON `null`, never numeric zero. This keeps an
unavailable score distinct from a real score of zero. `unavailable_reason`
reports the existing scoring gate reason, such as insufficient rule
assessment or low/unknown Analysis Confidence.

Parser Coverage may also be `null` when no supported or known unsupported
relevant syntax is present.

## Validation and errors

- Missing fields, wrong types, blank config, invalid UTF-8 file content, and
  malformed JSON return `422`.
- Unknown vendors return `422`. Supported explicit identifiers are
  `cisco_ios`, `aruba_aos_cx`, and `aruba_aos_s`; no identifier falls back to
  another platform pipeline.
- Config input larger than 1 MiB returns `413`.
- Unexpected internal failures return `500` with a generic response and no
  Python traceback or internal exception detail.

## V1 scope and limitations

The reference implementation analyzes Cisco IOS/IOS-XE syntax and documented
first-slice subsets for Aruba AOS-CX 10.12/10.13 and ArubaOS-Switch 2930F.
Parser, safe-config renderer, and coverage registry are selected together from
the explicit vendor identifier. There is no syntax auto-detection or
cross-vendor fallback. V1 does not provide authentication, production
hardening, rate limiting, TLS
termination, persistent storage, or background processing. Batch V1 is
synchronous and sequential. Vendor auto-detection and cross-vendor fallback
are not provided.

Deployments must add authentication, transport security, request controls,
and other operational protections outside this V1 application before any
production exposure.
