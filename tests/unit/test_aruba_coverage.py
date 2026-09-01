from pathlib import Path

from src.coverage.aruba_registry import ArubaCoverageRegistry
from src.domain.models import AnalysisConfidence, CoverageClass
from src.parsers.aruba.aos_cx import ArubaAOSCXParser
from src.services.coverage import CoverageService


SAMPLES = Path("samples/aruba")


def _coverage(name):
    raw_text = (SAMPLES / name).read_text()
    parser = ArubaAOSCXParser()
    return CoverageService(
        parser=parser,
        registry=ArubaCoverageRegistry(),
    ).evaluate(raw_text)


def test_aruba_supported_only_coverage():
    report = _coverage("coverage_supported_only.cfg")
    assert report.unsupported_relevant == 0
    assert report.unknown_relevance == 0
    assert report.coverage == 1.0
    assert report.analysis_confidence == AnalysisConfidence.HIGH


def test_aruba_mixed_coverage_uses_only_aruba_registry_families():
    report = _coverage("coverage_mixed.cfg")
    unsupported = [
        line for line in report.lines
        if line.classification == CoverageClass.UNSUPPORTED_RELEVANT
    ]
    assert [line.family_id for line in unsupported] == [
        "arp_inspection_trust",
    ]


def test_aruba_unknown_syntax_remains_unknown():
    report = _coverage("coverage_unknown.cfg")
    assert report.unknown_relevance == 1


def test_aruba_no_relevant_lines_produce_na_coverage():
    report = _coverage("coverage_no_relevant.cfg")
    assert report.coverage is None
    assert report.analysis_confidence == AnalysisConfidence.UNKNOWN
