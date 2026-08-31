from dataclasses import dataclass

from src.domain.coverage import CoverageReport
from src.domain.models import Finding, ParsedConfig, RuleEvaluation
from src.domain.scoring import PostureScore
from src.services.analyzer import AnalyzerService
from src.services.coverage import CoverageService
from src.services.scoring import ScoringCalculator


@dataclass(frozen=True)
class ApplicationAnalysisResult:
    config: ParsedConfig
    findings: tuple[Finding, ...]
    evaluations: dict[str, RuleEvaluation]
    coverage: CoverageReport
    posture: PostureScore


class AnalysisApplicationService:
    def __init__(self) -> None:
        self.analyzer = AnalyzerService()
        self.coverage = CoverageService()

    def analyze(self, raw_text: str) -> ApplicationAnalysisResult:
        config = self.analyzer.parser.parse(raw_text)
        evaluations = {
            rule.rule_id: rule.evaluate_detailed(config)
            for rule in self.analyzer.rules
        }
        findings = tuple(
            finding
            for evaluation in evaluations.values()
            for finding in evaluation.findings
        )
        coverage = self.coverage.evaluate(raw_text, config)
        posture = ScoringCalculator.calculate(
            evaluations,
            coverage.analysis_confidence,
        )
        return ApplicationAnalysisResult(
            config=config,
            findings=findings,
            evaluations=evaluations,
            coverage=coverage,
            posture=posture,
        )
