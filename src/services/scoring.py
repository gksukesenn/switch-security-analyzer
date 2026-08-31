from math import log2

from src.domain.models import (
    AnalysisConfidence,
    Confidence,
    RuleEvaluation,
    Severity,
)
from src.domain.scoring import PostureScore, RiskLevel, RulePenalty
from src.services.analyzer import AnalyzerService
from src.services.coverage import CoverageService


SEVERITY_WEIGHTS = {
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 4.0,
}

CONFIDENCE_MULTIPLIERS = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.70,
    Confidence.LOW: 0.40,
}


class ScoringCalculator:
    MINIMUM_ASSESSMENT_RATIO = 0.60
    MAXIMUM_EXPOSURE_FACTOR = 1.60

    @classmethod
    def calculate(
        cls,
        evaluations: dict[str, RuleEvaluation],
        analysis_confidence: AnalysisConfidence,
    ) -> PostureScore:
        cls._validate_evaluations(evaluations)
        total_rule_count = len(evaluations)
        assessed_rule_count = sum(
            evaluation.assessed_units > 0
            for evaluation in evaluations.values()
        )
        rule_assessment_ratio = (
            assessed_rule_count / total_rule_count
            if total_rule_count > 0
            else 0.0
        )

        unavailable_reason = cls._unavailable_reason(
            analysis_confidence,
            rule_assessment_ratio,
        )
        if unavailable_reason is not None:
            return PostureScore(
                score=None,
                display_score=None,
                risk_level=None,
                total_penalty=None,
                rule_assessment_ratio=rule_assessment_ratio,
                assessed_rule_count=assessed_rule_count,
                total_rule_count=total_rule_count,
                analysis_confidence=analysis_confidence,
                rule_penalties=(),
                unavailable_reason=unavailable_reason,
            )

        rule_penalties = tuple(
            cls._rule_penalty(rule_id, evaluation)
            for rule_id, evaluation in evaluations.items()
            if evaluation.findings
        )
        total_penalty = sum(
            rule_penalty.penalty for rule_penalty in rule_penalties
        )
        raw_score = max(0.0, 100.0 - total_penalty)
        display_score = round(raw_score)

        return PostureScore(
            score=raw_score,
            display_score=display_score,
            risk_level=cls._risk_level(raw_score),
            total_penalty=total_penalty,
            rule_assessment_ratio=rule_assessment_ratio,
            assessed_rule_count=assessed_rule_count,
            total_rule_count=total_rule_count,
            analysis_confidence=analysis_confidence,
            rule_penalties=rule_penalties,
            unavailable_reason=None,
        )

    @classmethod
    def _validate_evaluations(
        cls,
        evaluations: dict[str, RuleEvaluation],
    ) -> None:
        for rule_id, evaluation in evaluations.items():
            if evaluation.findings and evaluation.assessed_units == 0:
                raise ValueError(
                    f"{rule_id} produced findings without assessed units"
                )

    @classmethod
    def _rule_penalty(
        cls,
        rule_id: str,
        evaluation: RuleEvaluation,
    ) -> RulePenalty:
        finding_profiles = {
            (finding.severity, finding.confidence)
            for finding in evaluation.findings
        }
        if len(finding_profiles) != 1:
            raise ValueError(
                f"{rule_id} findings have inconsistent penalty profiles"
            )

        severity, confidence = finding_profiles.pop()
        base_penalty = (
            SEVERITY_WEIGHTS[severity]
            * CONFIDENCE_MULTIPLIERS[confidence]
        )
        affected_interfaces = {
            interface
            for finding in evaluation.findings
            for interface in finding.affected_interfaces
        }
        observed_units = max(
            len(evaluation.findings),
            len(affected_interfaces),
        )
        violating_units = min(
            evaluation.assessed_units,
            observed_units,
        )
        exposure_factor = min(
            cls.MAXIMUM_EXPOSURE_FACTOR,
            1 + 0.15 * log2(max(1, violating_units)),
        )

        return RulePenalty(
            rule_id=rule_id,
            base_penalty=base_penalty,
            violating_units=violating_units,
            exposure_factor=exposure_factor,
            penalty=base_penalty * exposure_factor,
        )

    @classmethod
    def _unavailable_reason(
        cls,
        analysis_confidence: AnalysisConfidence,
        rule_assessment_ratio: float,
    ) -> str | None:
        if analysis_confidence == AnalysisConfidence.LOW:
            return "analysis_confidence_low"
        if analysis_confidence == AnalysisConfidence.UNKNOWN:
            return "analysis_confidence_unknown"
        if rule_assessment_ratio < cls.MINIMUM_ASSESSMENT_RATIO:
            return "insufficient_rule_assessment"
        return None

    @staticmethod
    def _risk_level(raw_score: float) -> RiskLevel:
        if raw_score >= 90:
            return RiskLevel.LOW
        if raw_score >= 75:
            return RiskLevel.MODERATE
        if raw_score >= 50:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL


class ScoringService:
    def __init__(self) -> None:
        self.analyzer = AnalyzerService()
        self.coverage = CoverageService()

    def evaluate(self, raw_text: str) -> PostureScore:
        config = self.analyzer.parser.parse(raw_text)
        coverage_report = self.coverage.evaluate(raw_text, config)
        evaluations = {
            rule.rule_id: rule.evaluate_detailed(config)
            for rule in self.analyzer.rules
        }
        return ScoringCalculator.calculate(
            evaluations,
            coverage_report.analysis_confidence,
        )
