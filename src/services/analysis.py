from dataclasses import dataclass

from src.domain.coverage import CoverageReport
from src.domain.models import Finding, ParsedConfig, RuleEvaluation
from src.domain.scoring import PostureScore
from src.domain.vendors import Vendor
from src.services.analyzer import AnalyzerService
from src.services.coverage import CoverageService
from src.services.scoring import ScoringCalculator
from src.services.vendor_selection import VendorComponentSelector


@dataclass(frozen=True)
class ApplicationAnalysisResult:
    config: ParsedConfig
    findings: tuple[Finding, ...]
    evaluations: dict[str, RuleEvaluation]
    coverage: CoverageReport
    posture: PostureScore


class AnalysisApplicationService:
    def __init__(
        self,
        component_selector: VendorComponentSelector | None = None,
    ) -> None:
        self.component_selector = (
            component_selector
            if component_selector is not None
            else VendorComponentSelector()
        )

    def analyze(
        self,
        raw_text: str,
        vendor: Vendor = Vendor.CISCO_IOS,
    ) -> ApplicationAnalysisResult:
        components = self.component_selector.components_for(vendor)
        analyzer = AnalyzerService(
            safe_config_renderer=components.renderer,
            parser=components.parser,
        )
        coverage_service = CoverageService(
            parser=components.parser,
            registry=components.coverage_registry,
        )
        config = analyzer.parser.parse(raw_text)
        registered_rule_ids = frozenset(
            rule.rule_id for rule in analyzer.rules
        )
        undeclared_rule_ids = (
            components.supported_rule_ids - registered_rule_ids
        )
        if undeclared_rule_ids:
            raise ValueError(
                "platform supports unregistered rule IDs: "
                f"{sorted(undeclared_rule_ids)}"
            )
        evaluations = {
            rule.rule_id: (
                rule.evaluate_detailed(config)
                if rule.rule_id in components.supported_rule_ids
                else RuleEvaluation([], 0)
            )
            for rule in analyzer.rules
        }
        findings = tuple(
            finding
            for evaluation in evaluations.values()
            for finding in evaluation.findings
        )
        coverage = coverage_service.evaluate(raw_text, config)
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
