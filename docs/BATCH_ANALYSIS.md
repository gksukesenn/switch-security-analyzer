# Batch Analysis V1

Batch Analysis accepts up to 50 Cisco IOS/IOS-XE, Aruba AOS-CX, and
ArubaOS-Switch configurations in a single request. Device identifiers must be
non-empty and unique, and every device must explicitly select a supported
vendor.

## Architecture

`BatchAnalysisService` is an application-level orchestration and aggregation
layer only:

```text
device 1 --\
device 2 ----> AnalysisApplicationService.analyze(config, vendor)
device 3 --/                         |
                                      +--> deterministic aggregation
```

Every device reuses the existing single-device parser, rules, coverage,
Analysis Confidence, and scoring pipeline. Batch code does not invoke those
components independently or change their semantics.

## Execution and failure policy

V1 processes devices sequentially and preserves request order. It does not use
threads, asynchronous orchestration, background jobs, or queues.

The whole request is rejected for an empty batch, duplicate device IDs,
unsupported vendors, blank configs, or more than `MAX_BATCH_DEVICES = 50`
devices. Partial success is not supported. Each config retains the API's 1 MiB
UTF-8 limit. V1 adds no aggregate byte budget; deployments may enforce a
request-body limit outside the application.

### Failure policy trade-off

Batch Analysis V1 does not support partial success.

If an unexpected analysis error occurs for any device after request validation,
the whole batch request fails rather than returning a mixture of successful and
failed device results.

This keeps the V1 response contract deterministic and avoids silently
presenting an incomplete batch as successful. The trade-off is that one
problematic device can cause otherwise successful results in the same batch to
be discarded.

A future version may introduce explicit per-device success/error status.

### Request-size limitation

The API enforces the existing 1 MiB configuration limit per device and a
maximum of 50 devices per batch. V1 does not currently enforce a separate
aggregate batch-body byte limit, so the theoretical configuration payload can
approach 50 MiB before JSON/protocol overhead.

Deployment-level request limits should be considered during production
hardening.

## Statistics and unavailable scores

The result reports total device and finding counts, scored and unscored device
counts, the same four counts per vendor, and exact finding counts per category.
Only vendors and categories present in the batch appear in their maps.

An unavailable posture remains `null` and increments `unscored_devices`; it is
never converted to zero. V1 deliberately does not calculate average posture
scores, average risks, or cross-vendor mean scores because excluding unscored
devices could make comparisons misleading.
