import argparse
from pathlib import Path

from src.services.analyzer import AnalyzerService


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a Cisco IOS/IOS-XE switch configuration."
    )

    parser.add_argument(
        "config_file",
        help="Path to the switch configuration file.",
    )

    args = parser.parse_args()

    config_path = Path(args.config_file)

    raw_config = config_path.read_text(
        encoding="utf-8"
    )

    analyzer = AnalyzerService()

    findings = analyzer.analyze(raw_config)

    if not findings:
        print("No findings.")
        return

    for finding in findings:
        print("=" * 60)
        print(f"Rule:       {finding.rule_id}")
        print(f"Title:      {finding.title}")
        print(f"Severity:   {finding.severity.value.upper()}")
        print(f"Confidence: {finding.confidence.value.upper()}")
        print(f"Risk score: {finding.risk_score}/10")

        if finding.affected_interfaces:
            print()
            print("Affected interfaces:")
            for interface in finding.affected_interfaces:
                print(f"  - {interface}")

        print()
        print("Technical impact:")
        print(f"  {finding.technical_impact}")

        print()
        print("Remediation:")
        print(f"  {finding.remediation}")

        print()
        print("Safe configuration example:")
        print(finding.safe_config_example)

        print()
        print("Evidence:")
        for evidence in finding.evidence:
            print(
                f"  line {evidence.line_number}: "
                f"{evidence.text.strip()}"
            )

        print("=" * 60)


if __name__ == "__main__":
    main()
