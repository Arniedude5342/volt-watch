"""Tests for #37: a failed systemd unit is never reported.

A host can be reachable, patched and safe by every other check this tool runs
and still be broken: a unit in `failed` state means a service the machine
depends on is down. A dead sshd on a machine you reach only over the network
is an outage, not a warning.
"""

from volt_watch import collector
from volt_watch.checks import failed_units_check


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _run(monkeypatch, stdout="", returncode=0):
    def fake_run(cmd, **kwargs):
        return _Result(stdout, returncode)

    monkeypatch.setattr(collector.subprocess, "run", fake_run)


# systemctl --failed --no-legend --plain, one line per failed unit.
FAILED_TWO = (
    "sshd.service loaded failed failed OpenBSD Secure Shell server\n"
    "some-user-thing.service loaded failed failed A thing that died\n"
)


def test_the_reader_parses_each_failed_unit(monkeypatch):
    _run(monkeypatch, FAILED_TWO)

    units = collector.failed_units()

    assert [u["name"] for u in units] == [
        "sshd.service",
        "some-user-thing.service",
    ]
    assert units[0]["load"] == "loaded"
    assert units[0]["sub"] == "failed"


def test_no_failed_units_is_an_empty_list(monkeypatch):
    _run(monkeypatch, "")

    assert collector.failed_units() == []


def test_a_systemctl_that_fails_is_unknown_not_empty(monkeypatch):
    """The same rule as everywhere else: "could not ask" is not "nothing wrong"."""
    _run(monkeypatch, "", returncode=1)

    assert collector.failed_units() is None


def test_a_missing_systemctl_is_unknown(monkeypatch):
    def boom(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(collector.subprocess, "run", boom)

    assert collector.failed_units() is None


def test_a_failed_sshd_is_critical(monkeypatch):
    """On a host you reach over the network, a dead sshd is the outage."""
    _run(monkeypatch, FAILED_TWO)

    findings = failed_units_check(collector.failed_units())

    assert findings[0].severity.value == "critical"
    assert "sshd.service" in findings[0].message


def test_an_unremarkable_failed_unit_is_a_warning(monkeypatch):
    _run(monkeypatch, "some-user-thing.service loaded failed failed A thing\n")

    findings = failed_units_check(collector.failed_units())

    assert findings[0].severity.value == "warning"


def test_a_network_manager_is_critical_too(monkeypatch):
    """Losing the network stack makes the host unreachable the same way."""
    _run(monkeypatch, "NetworkManager.service loaded failed failed Network Manager\n")

    assert failed_units_check(collector.failed_units())[0].severity.value == "critical"


def test_no_failed_units_is_no_finding(monkeypatch):
    _run(monkeypatch, "")

    assert failed_units_check(collector.failed_units()) == []


def test_an_unreadable_state_is_not_a_finding():
    assert failed_units_check(None) == []


def test_the_evidence_names_every_failed_unit(monkeypatch):
    _run(monkeypatch, FAILED_TWO)

    findings = failed_units_check(collector.failed_units())

    assert set(findings[0].evidence["units"]) == {
        "sshd.service",
        "some-user-thing.service",
    }
