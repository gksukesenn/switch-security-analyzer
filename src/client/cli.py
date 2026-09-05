import argparse
import sys
from pathlib import Path
from typing import Any, Sequence, TextIO

from src.client.http import (
    DEFAULT_SERVER_URL,
    AnalyzerClientError,
    AnalyzerHttpClient,
)
from src.domain.vendors import Vendor


INPUT_ERROR = 2
CLIENT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze a switch configuration through the HTTP API."
    )
    parser.add_argument(
        "--server",
        default=DEFAULT_SERVER_URL,
        help=f"Analyzer server URL (default: {DEFAULT_SERVER_URL}).",
    )
    parser.add_argument(
        "--vendor",
        required=True,
        choices=[vendor.value for vendor in Vendor],
        help="Switch vendor/platform identifier.",
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--file",
        type=Path,
        help="Local configuration file to upload.",
    )
    input_group.add_argument(
        "--stdin",
        action="store_true",
        help="Read raw configuration text from standard input.",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    input_stream = stdin or sys.stdin
    output_stream = stdout or sys.stdout
    error_stream = stderr or sys.stderr

    if args.file is not None and (
        not args.file.exists() or not args.file.is_file()
    ):
        print(
            "Error: configuration file does not exist or is not a file.",
            file=error_stream,
        )
        return INPUT_ERROR

    client = AnalyzerHttpClient(args.server)
    try:
        if args.file is not None:
            result = client.analyze_file(args.file, args.vendor)
        else:
            config = input_stream.read()
            if not config.strip():
                print("Error: standard input is empty.", file=error_stream)
                return INPUT_ERROR
            result = client.analyze_text(config, args.vendor)
    except AnalyzerClientError as exception:
        print(f"Error: {exception}", file=error_stream)
        return CLIENT_ERROR

    render_analysis(result, output_stream)
    return 0


def render_analysis(result: dict[str, Any], output: TextIO) -> None:
    device = result["device"]
    analysis = result["analysis"]
    posture = result["posture"]
    findings = result["findings"]

    print("Switch Security Analysis", file=output)
    print("=" * 60, file=output)
    print(f"Vendor:              {_display(device.get('vendor'))}", file=output)
    print(f"Hostname:            {_display(device.get('hostname'))}", file=output)
    print(f"Security score:      {_display(posture.get('score'))}", file=output)
    print(f"Risk level:          {_display(posture.get('risk_level'))}", file=output)
    print(
        f"Parser coverage:     {_percentage(analysis.get('parser_coverage'))}",
        file=output,
    )
    print(
        f"Analysis confidence: {_display(analysis.get('analysis_confidence'))}",
        file=output,
    )
    print(
        "Rules assessed:      "
        f"{_display(analysis.get('assessed_rule_count'))} of "
        f"{_display(analysis.get('total_rule_count'))}",
        file=output,
    )
    print(
        f"Assessment ratio:    {_percentage(analysis.get('rule_assessment_ratio'))}",
        file=output,
    )
    print(f"Findings:            {len(findings)}", file=output)

    if not findings:
        print("\nNo findings reported within the assessed scope.", file=output)
        return

    for finding in findings:
        print("\n" + "-" * 60, file=output)
        print(
            f"{_display(finding.get('rule_id'))}: "
            f"{_display(finding.get('title'))}",
            file=output,
        )
        print(f"Severity:   {_display(finding.get('severity'))}", file=output)
        print(f"Confidence: {_display(finding.get('confidence'))}", file=output)
        risk_score = finding.get("risk_score")
        print(
            f"Risk score: {str(risk_score) + '/10' if risk_score is not None else 'N/A'}",
            file=output,
        )
        interfaces = finding.get("affected_interfaces") or []
        displayed_interfaces = ", ".join(map(str, interfaces))
        print(
            f"Affected interfaces: {displayed_interfaces or 'None specified'}",
            file=output,
        )
        print("\nTechnical impact:", file=output)
        print(f"  {_display(finding.get('technical_impact'))}", file=output)
        print("\nEvidence:", file=output)
        for evidence in finding.get("evidence") or []:
            print(
                f"  line {_display(evidence.get('line_number'))}: "
                f"{_display(evidence.get('text'))}",
                file=output,
            )
        print("\nRemediation:", file=output)
        print(f"  {_display(finding.get('remediation'))}", file=output)
        print("\nSafe configuration example:", file=output)
        print(_display(finding.get("safe_config_example")), file=output)


def _display(value: Any) -> str:
    return "N/A" if value is None else str(value)


def _percentage(value: Any) -> str:
    if value is None:
        return "N/A"
    return f"{float(value) * 100:.1f}%"


if __name__ == "__main__":
    raise SystemExit(main())
