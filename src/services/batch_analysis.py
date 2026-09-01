from dataclasses import dataclass

from src.domain.vendors import Vendor
from src.services.analysis import (
    AnalysisApplicationService,
    ApplicationAnalysisResult,
)


MAX_BATCH_DEVICES = 50


class InvalidBatchError(ValueError):
    pass


@dataclass(frozen=True)
class BatchDeviceInput:
    device_id: str
    vendor: Vendor
    config: str


@dataclass(frozen=True)
class BatchDeviceResult:
    device_id: str
    vendor: Vendor
    analysis: ApplicationAnalysisResult


@dataclass(frozen=True)
class VendorStatistics:
    device_count: int
    finding_count: int
    scored_device_count: int
    unscored_device_count: int


@dataclass(frozen=True)
class BatchStatistics:
    total_devices: int
    total_findings: int
    scored_devices: int
    unscored_devices: int
    by_vendor: dict[str, VendorStatistics]
    by_category: dict[str, int]


@dataclass(frozen=True)
class BatchAnalysisResult:
    devices: tuple[BatchDeviceResult, ...]
    statistics: BatchStatistics


class BatchAnalysisService:
    def __init__(
        self,
        analysis_service: AnalysisApplicationService | None = None,
    ) -> None:
        self.analysis_service = (
            analysis_service
            if analysis_service is not None
            else AnalysisApplicationService()
        )

    def analyze(
        self,
        devices: list[BatchDeviceInput],
    ) -> BatchAnalysisResult:
        self._validate(devices)
        results = tuple(
            BatchDeviceResult(
                device_id=device.device_id,
                vendor=device.vendor,
                analysis=self.analysis_service.analyze(
                    device.config,
                    device.vendor,
                ),
            )
            for device in devices
        )
        return BatchAnalysisResult(
            devices=results,
            statistics=self._aggregate(results),
        )

    @staticmethod
    def _validate(devices: list[BatchDeviceInput]) -> None:
        if not devices:
            raise InvalidBatchError("batch must contain at least one device")
        if len(devices) > MAX_BATCH_DEVICES:
            raise InvalidBatchError(
                f"batch exceeds the {MAX_BATCH_DEVICES}-device limit"
            )

        device_ids: set[str] = set()
        for device in devices:
            if not device.device_id.strip():
                raise InvalidBatchError("device_id must not be empty")
            if device.device_id in device_ids:
                raise InvalidBatchError(
                    f"duplicate device_id: {device.device_id}"
                )
            if not device.config.strip():
                raise InvalidBatchError(
                    f"config must not be empty for {device.device_id}"
                )
            device_ids.add(device.device_id)

    @staticmethod
    def _aggregate(
        devices: tuple[BatchDeviceResult, ...],
    ) -> BatchStatistics:
        vendor_counts: dict[str, list[int]] = {}
        category_counts: dict[str, int] = {}
        total_findings = 0
        scored_devices = 0

        for device in devices:
            finding_count = len(device.analysis.findings)
            is_scored = device.analysis.posture.score is not None
            total_findings += finding_count
            scored_devices += is_scored

            counts = vendor_counts.setdefault(
                device.vendor.value,
                [0, 0, 0, 0],
            )
            counts[0] += 1
            counts[1] += finding_count
            counts[2] += is_scored
            counts[3] += not is_scored

            for finding in device.analysis.findings:
                category_counts[finding.category] = (
                    category_counts.get(finding.category, 0) + 1
                )

        by_vendor = {
            vendor.value: VendorStatistics(*vendor_counts[vendor.value])
            for vendor in Vendor
            if vendor.value in vendor_counts
        }
        return BatchStatistics(
            total_devices=len(devices),
            total_findings=total_findings,
            scored_devices=scored_devices,
            unscored_devices=len(devices) - scored_devices,
            by_vendor=by_vendor,
            by_category=dict(sorted(category_counts.items())),
        )
