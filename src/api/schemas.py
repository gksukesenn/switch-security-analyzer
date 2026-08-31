from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.domain.vendors import Vendor


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(strict=True)

    config: str
    vendor: Annotated[Vendor, Field(strict=False)] = Vendor.CISCO_IOS

    @field_validator("config")
    @classmethod
    def config_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("config must not be empty or whitespace-only")
        return value


class HealthResponse(BaseModel):
    status: str


class DeviceResponse(BaseModel):
    vendor: str
    hostname: str | None


class AnalysisResponse(BaseModel):
    parser_coverage: float | None
    unknown_ratio: float
    analysis_confidence: str
    assessed_rule_count: int
    total_rule_count: int
    rule_assessment_ratio: float


class RulePenaltyResponse(BaseModel):
    rule_id: str
    base_penalty: float
    exposure_factor: float
    violating_units: int
    penalty: float


class PostureResponse(BaseModel):
    score: float | None
    display_score: int | None
    risk_level: str | None
    total_penalty: float | None
    unavailable_reason: str | None
    rule_penalties: list[RulePenaltyResponse]


class EvidenceResponse(BaseModel):
    line_number: int
    text: str


class FindingResponse(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    technical_impact: str
    remediation: str
    safe_config_example: str
    affected_interfaces: list[str]
    evidence: list[EvidenceResponse]


class AnalyzeResponse(BaseModel):
    device: DeviceResponse
    analysis: AnalysisResponse
    posture: PostureResponse
    findings: list[FindingResponse]
