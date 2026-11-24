"""The account database: an empty password field is a finding."""

import pytest

from volt_watch.checks import empty_password_accounts_check
from volt_watch.collector import empty_password_accounts
from volt_watch.finding import Finding
from volt_watch.severity import Severity


SHADOW = """\
root::19600:0:99999:7:::
yunare:!:19600:0:99999:7:::
daemon:*:19600:0:99999:7:::
alice:$6$rounds=5000$salt$hash:19600:0:99999:7:::
"""


def test_only_the_empty_password_field_is_reported(tmp_path):
    shadow = tmp_path / "shadow"
    shadow.write_text(SHADOW, encoding="utf-8")

    assert empty_password_accounts(str(shadow)) == [{"name": "root"}]


def test_a_missing_account_database_is_not_unknown(tmp_path):
    """A non-Linux host has no /etc/shadow and must not look unreadable."""

    assert empty_password_accounts(str(tmp_path / "absent")) == []


def test_an_existing_database_that_cannot_be_read_is_none(tmp_path, monkeypatch):
    shadow = tmp_path / "shadow"
    shadow.write_text("root::\n", encoding="utf-8")

    def denied(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("pathlib.Path.read_text", denied)

    assert empty_password_accounts(str(shadow)) is None


def test_malformed_lines_are_skipped(tmp_path):
    shadow = tmp_path / "shadow"
    shadow.write_text(
        "root::19600:0:99999:7:::\n"
        "not-a-shadow-line\n"
        ":missing-name\n"
        "\n",
        encoding="utf-8",
    )

    assert empty_password_accounts(str(shadow)) == [{"name": "root"}]


def test_a_database_with_no_passwordless_accounts_is_clean():
    assert empty_password_accounts_check([]) == []


def test_an_unreadable_database_reports_the_unknown():
    findings = empty_password_accounts_check(None)

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.check == "security.shadow_unreadable"
    assert finding.severity is Severity.WARNING


def test_passwordless_accounts_are_critical_and_name_the_accounts():
    findings = empty_password_accounts_check([{"name": "root"}, {"name": "yunare"}])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check == "security.empty_password_accounts"
    assert finding.severity is Severity.CRITICAL
    assert "root" in finding.message
    assert "yunare" in finding.message
    assert finding.evidence["accounts"] == ["root", "yunare"]


def test_the_finding_never_carries_a_hash():
    findings = empty_password_accounts_check([{"name": "root"}])

    assert "$" not in repr(findings[0].as_dict())


def test_the_security_group_runs_the_check(monkeypatch):
    from volt_watch import auditor, collector

    monkeypatch.setattr(collector, "empty_password_accounts", lambda: [])

    assert auditor.CHECKS["security"][0]() == []
