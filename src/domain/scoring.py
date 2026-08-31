from dataclasses import dataclass
from enum import Enum

from src.domain.models import AnalysisConfidence


class RiskLevel(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class RulePenalty:
    rule_id: str
    base_penalty: float
    violating_units: int
    exposure_factor: float
    penalty: float


@dataclass(frozen=True)
class PostureScore:
    score: float | None
    display_score: int | None
    risk_level: RiskLevel | None
    total_penalty: float | None
    rule_assessment_ratio: float
    assessed_rule_count: int
    total_rule_count: int
    analysis_confidence: AnalysisConfidence
    rule_penalties: tuple[RulePenalty, ...]
    unavailable_reason: str | None
