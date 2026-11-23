"""Tests for #40: orphaned packages are invisible, and they hold old kernels.

On a rolling release the orphans accumulate: each orphaned kernel package is
hundreds of megabytes, and they are exactly what keeps old, unpatched code on
the disk after a power cut. A machine can be fully updated and still carry a
year of dead weight, while packages.outdated reads 0.
"""

from volt_watch import collector
from volt_watch.checks import orphaned_packages_check


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _run(monkeypatch, stdout="", returncode=0):
    def fake_run(cmd, **kwargs):
        return _Result(stdout, returncode)

    monkeypatch.setattr(collector.subprocess, "run", fake_run)


# `pacman -Qdt`: one package per entry, name and version on the first line,
# the explanation indented below it.
ORPHANS_TWO = (
    "linux-lts 7.1.0-1\n"
    "    Installed as a dependency for another package, now unrequired\n"
    "some-tool 1.2.3-1\n"
    "    Installed as a dependency for another package, now unrequired\n"
)


def test_the_reader_returns_name_and_version(monkeypatch):
    _run(monkeypatch, ORPHANS_TWO)

    assert collector.orphaned_packages() == [
        {"name": "linux-lts", "version": "7.1.0-1"},
        {"name": "some-tool", "version": "1.2.3-1"},
    ]


def test_no_orphans_is_an_empty_list(monkeypatch):
    """pacman exits 1 when the query matched nothing, like checkupdates."""
    _run(monkeypatch, "", returncode=1)

    assert collector.orphaned_packages() == []


def test_a_pacman_that_fails_is_unknown_not_empty(monkeypatch):
    """Anything past pacman's "matched nothing" exit 1 is a real failure."""
    _run(monkeypatch, "", returncode=2)

    assert collector.orphaned_packages() is None


def test_a_missing_pacman_is_unknown(monkeypatch):
    def boom(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(collector.subprocess, "run", boom)

    assert collector.orphaned_packages() is None


def test_an_orphan_is_info():
    findings = orphaned_packages_check(
        [{"name": "some-tool", "version": "1.2.3-1"}]
    )

    assert [f.check for f in findings] == ["packages.orphaned"]
    assert findings[0].severity.value == "info"


def test_an_orphaned_kernel_is_a_warning(monkeypatch):
    """An orphan that is a kernel or a boot-path library is worth more."""
    findings = orphaned_packages_check([{"name": "linux-lts", "version": "7.1.0-1"}])

    assert findings[0].severity.value == "warning"


def test_an_orphaned_nvidia_driver_is_a_warning():
    findings = orphaned_packages_check([{"name": "nvidia-7xx", "version": "1.0-1"}])

    assert findings[0].severity.value == "warning"


def test_no_orphans_is_no_finding(monkeypatch):
    _run(monkeypatch, "", returncode=1)

    assert orphaned_packages_check(collector.orphaned_packages()) == []


def test_an_unreadable_state_is_not_a_finding():
    assert orphaned_packages_check(None) == []


def test_the_remedy_never_says_to_remove_without_reviewing():
    """`pacman -Rns` takes the dependents with it; the text must say so."""
    findings = orphaned_packages_check([{"name": "linux-lts", "version": "7.1.0-1"}])

    assert "pacman -Rns" in findings[0].remedy
    assert "after" in findings[0].remedy.lower()
