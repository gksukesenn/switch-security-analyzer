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
    assert "Affected interfaces:" in output
    assert "  - GigabitEthernet1/0/5" in output
    assert "Safe configuration example:" in output
    assert "interface GigabitEthernet1/0/5\n" in output
    assert " switchport mode access\n" in output
    assert " switchport access vlan 10\n" in output
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


def test_cli_omits_empty_affected_interfaces_for_management_finding(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        sys,
        "argv",
        ["cli", "samples/cisco/mgmt_001_vty_telnet_enabled.cfg"],
    )

    main()

    output = capsys.readouterr().out

    assert "Rule:       MGMT-001" in output
    assert "Affected interfaces:" not in output
    assert "line vty 0 4" in output
    assert " transport input ssh" in output


def test_cli_prints_mgmt_002_without_empty_affected_interfaces(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        sys,
        "argv",
        ["cli", "samples/cisco/mgmt_002_http_enabled.cfg"],
    )

    main()

    output = capsys.readouterr().out
    assert "Rule:       MGMT-002" in output
    assert "Severity:   HIGH" in output
    assert "Confidence: HIGH" in output
    assert "Affected interfaces:" not in output
    assert "Technical impact:" in output
    assert "Remediation:" in output
    assert "Safe configuration example:\nno ip http server" in output
    assert "Evidence:" in output
    assert "line 2: ip http server" in output
