from dataclasses import dataclass

from src.domain.models import AnalysisConfidence, CoverageClass, SourceLine


@dataclass(frozen=True)
class CoverageLine:
    source_line: SourceLine
    classification: CoverageClass
    family_id: str | None = None


@dataclass(frozen=True)
class CoverageReport:
    lines: tuple[CoverageLine, ...]
    supported_relevant: int
    unsupported_relevant: int
    out_of_scope: int
    unknown_relevance: int
    coverage: float | None
    unknown_ratio: float
    analysis_confidence: AnalysisConfidence
