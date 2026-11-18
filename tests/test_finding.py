"""Tests for the Finding value object."""

from volt_watch.finding import Finding
from volt_watch.severity import Severity


def test_finding_holds_its_fields():
    finding = Finding(
        check="sshd.bind",
        severity=Severity.CRITICAL,
        message="sshd listens on every interface",
        remedy="Allow port 22 on tailscale0 only",
    )

    assert finding.check == "sshd.bind"
    assert finding.severity is Severity.CRITICAL
    assert finding.message == "sshd listens on every interface"
    assert finding.remedy == "Allow port 22 on tailscale0 only"


def test_finding_evidence_defaults_to_empty_dict():
    finding = Finding(check="x", severity=Severity.INFO, message="m")

    assert finding.evidence == {}


def test_as_dict_serialises_severity_as_its_value():
    finding = Finding(
        check="x",
        severity=Severity.WARNING,
        message="m",
        remedy="r",
        evidence={"port": 22},
    )

    assert finding.as_dict() == {
        "check": "x",
        "severity": "warning",
        "message": "m",
        "remedy": "r",
        "evidence": {"port": 22},
    }
