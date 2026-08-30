import sys

from src.cli import main


def test_cli_prints_dhcp_003_finding(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["cli", "samples/cisco/dhcp_003_trusted_access.cfg"],
    )

    main()

    output = capsys.readouterr().out

    assert "Rule:       DHCP-003" in output
    assert "Severity:   HIGH" in output
    assert "Confidence: MEDIUM" in output
    assert "  - GigabitEthernet1/0/5" in output
    assert "  line 2: ip dhcp snooping" in output
    assert "  line 9: ip dhcp snooping trust" in output


def test_cli_prints_no_findings_for_safe_config(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["cli", "samples/cisco/dhcp_003_safe_access.cfg"],
    )

    main()

    assert capsys.readouterr().out == "No findings.\n"
