from collections import Counter

from src.coverage.cisco_registry import (
    is_out_of_scope,
    match_unsupported_family,
)
from src.domain.coverage import CoverageLine, CoverageReport
from src.domain.models import (
    AnalysisConfidence,
    CoverageClass,
    ParsedConfig,
    SourceLine,
)
from src.parsers.cisco.ios import CiscoIOSParser


class CoverageCalculator:
    @staticmethod
    def calculate(
        supported_relevant: int,
        unsupported_relevant: int,
        out_of_scope: int,
        unknown_relevance: int,
    ) -> tuple[float | None, float, AnalysisConfidence]:
        relevant_total = supported_relevant + unsupported_relevant
        coverage = (
            supported_relevant / relevant_total
            if relevant_total > 0
            else None
        )

        uncertainty_total = relevant_total + unknown_relevance
        unknown_ratio = (
            unknown_relevance / uncertainty_total
            if uncertainty_total > 0
            else 0.0
        )

        confidence = CoverageCalculator._confidence(
            coverage,
            unknown_ratio,
        )
        return coverage, unknown_ratio, confidence

    @staticmethod
    def _confidence(
        coverage: float | None,
        unknown_ratio: float,
    ) -> AnalysisConfidence:
        if coverage is None:
            return AnalysisConfidence.UNKNOWN

        if coverage >= 0.80:
            confidence = AnalysisConfidence.HIGH
        elif coverage >= 0.60:
            confidence = AnalysisConfidence.MEDIUM
        else:
            confidence = AnalysisConfidence.LOW

        if unknown_ratio > 0.40:
            return AnalysisConfidence.LOW
        if unknown_ratio > 0.20:
            return {
                AnalysisConfidence.HIGH: AnalysisConfidence.MEDIUM,
                AnalysisConfidence.MEDIUM: AnalysisConfidence.LOW,
                AnalysisConfidence.LOW: AnalysisConfidence.LOW,
            }[confidence]
        return confidence


class CoverageService:
    def __init__(self) -> None:
        self.parser = CiscoIOSParser()

    def evaluate(
        self,
        raw_text: str,
        parsed_config: ParsedConfig | None = None,
    ) -> CoverageReport:
        config = parsed_config or self.parser.parse(raw_text)
        meaningful_lines = tuple(
            SourceLine(line_number, raw_line.rstrip())
            for line_number, raw_line in enumerate(raw_text.splitlines(), 1)
            if raw_line.strip() and raw_line.strip() != "!"
        )
        meaningful_numbers = {line.line_number for line in meaningful_lines}
        parsed_numbers = set(config.parsed_line_coverage)
        unparsed_numbers = {line.line_number for line in config.unparsed_lines}

        if parsed_numbers & unparsed_numbers:
            raise ValueError("a line cannot be both parsed and unparsed")
        if parsed_numbers | unparsed_numbers != meaningful_numbers:
            raise ValueError("every meaningful line must be parsed or unparsed")

        classified_lines = tuple(
            self._classify_line(line, config)
            for line in meaningful_lines
        )
        counts = Counter(line.classification for line in classified_lines)
        supported = counts[CoverageClass.SUPPORTED_RELEVANT]
        unsupported = counts[CoverageClass.UNSUPPORTED_RELEVANT]
        out_of_scope = counts[CoverageClass.OUT_OF_SCOPE]
        unknown = counts[CoverageClass.UNKNOWN_RELEVANCE]
        coverage, unknown_ratio, confidence = CoverageCalculator.calculate(
            supported,
            unsupported,
            out_of_scope,
            unknown,
        )

        return CoverageReport(
            lines=classified_lines,
            supported_relevant=supported,
            unsupported_relevant=unsupported,
            out_of_scope=out_of_scope,
            unknown_relevance=unknown,
            coverage=coverage,
            unknown_ratio=unknown_ratio,
            analysis_confidence=confidence,
        )

    @staticmethod
    def _classify_line(
        line: SourceLine,
        config: ParsedConfig,
    ) -> CoverageLine:
        parsed_class = config.parsed_line_coverage.get(line.line_number)
        if parsed_class is not None:
            return CoverageLine(line, parsed_class)

        command = line.text.strip()
        family = match_unsupported_family(command)
        if family is not None:
            return CoverageLine(
                line,
                CoverageClass.UNSUPPORTED_RELEVANT,
                family.family_id,
            )
        if is_out_of_scope(command):
            return CoverageLine(line, CoverageClass.OUT_OF_SCOPE)
        return CoverageLine(line, CoverageClass.UNKNOWN_RELEVANCE)
