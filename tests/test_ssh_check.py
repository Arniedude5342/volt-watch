"""Tests for the SSH exposure check."""

from volt_watch.checks import ssh_exposure_check


def test_no_finding_when_ssh_is_allowed_only_on_tailscale():
    rules = [
        {"port": "22", "action": "ALLOW", "interface": "tailscale0"},
        {"port": "22", "action": "DENY", "interface": ""},
    ]

    assert ssh_exposure_check(rules) == []


def test_reports_ssh_allowed_on_a_public_interface():
    rules = [{"port": "22", "action": "ALLOW", "interface": ""}]

    findings = ssh_exposure_check(rules)

    assert [f.check for f in findings] == ["sshd.exposed"]
    assert findings[0].severity.value == "critical"
    assert findings[0].remedy


def test_ignores_rules_for_other_ports():
    rules = [{"port": "8080", "action": "ALLOW", "interface": ""}]

    assert ssh_exposure_check(rules) == []


def test_ignores_deny_rules_on_the_public_interface():
    rules = [{"port": "22", "action": "DENY", "interface": ""}]

    assert ssh_exposure_check(rules) == []


def test_reports_when_ssh_is_not_restricted_and_the_default_allows():
    """With a permissive default, an unmentioned port 22 is reachable."""
    rules = [{"port": "53317", "action": "ALLOW", "interface": ""}]

    findings = ssh_exposure_check(rules, default_incoming="allow")

    assert [f.check for f in findings] == ["sshd.unrestricted"]
    assert findings[0].severity.value == "warning"


def test_silent_when_the_default_denies_and_ssh_is_unmentioned():
    """With a deny default, an unmentioned port 22 is closed."""
    rules = [{"port": "53317", "action": "ALLOW", "interface": ""}]

    assert ssh_exposure_check(rules, default_incoming="deny") == []
