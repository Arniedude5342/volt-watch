"""Tests for #39: a kernel newer than the running one is not reported.

After pacman -Syu brings a new kernel, the running one stays the old until a
reboot. A host that loses power right then -- the exact scenario this tool
exists for -- boots the old kernel with every fix that shipped in the new one
absent, while packages.outdated reads 0 because the update is installed.
"""

from volt_watch import collector
from volt_watch.checks import is_pending_kernel_boot, kernel_reboot_check


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _run(monkeypatch, uname="7.2.14-1-omarchy", packages="linux-omarchy 7.2.15-1\n"):
    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["uname", "-r"]:
            return _Result(uname + "\n")
        return _Result(packages)

    monkeypatch.setattr(collector.subprocess, "run", fake_run)


# --- the version comparison, which is where the bugs live ---


def test_a_distro_suffix_is_stripped_from_the_running_release():
    assert collector.normalize_release("7.2.15-1-omarchy") == "7.2.15-1"


def test_a_plain_release_is_left_alone():
    assert collector.normalize_release("7.2.15-1") == "7.2.15-1"


def test_an_aarch64_style_release_keeps_its_pkgrel():
    assert collector.normalize_release("6.1.0-1-aarch64") == "6.1.0-1"


def test_a_running_kernel_older_than_the_installed_one_is_pending():
    assert is_pending_kernel_boot("7.2.14-1", ["7.2.15-1"]) is True


def test_the_same_release_is_not_pending():
    assert is_pending_kernel_boot("7.2.15-1", ["7.2.15-1"]) is False


def test_the_running_release_with_a_distro_suffix_compares_correctly():
    """7.2.15-1-omarchy is the same kernel as linux-omarchy 7.2.15-1."""
    assert is_pending_kernel_boot("7.2.15-1-omarchy", ["7.2.15-1"]) is False


def test_a_newer_patch_level_is_pending():
    assert is_pending_kernel_boot("7.2.15-1", ["7.2.16-1"]) is True


def test_a_newer_major_is_pending():
    assert is_pending_kernel_boot("7.2.15-1", ["8.0.0-1"]) is True


def test_a_newer_pkgrel_is_pending():
    """Same upstream kernel, rebuilt by the distro: still needs the reboot."""
    assert is_pending_kernel_boot("7.2.15-1", ["7.2.15-2"]) is True


def test_the_newest_installed_kernel_wins():
    assert is_pending_kernel_boot("7.2.14-1", ["7.2.15-1", "7.2.10-1"]) is True


def test_no_installed_kernel_is_not_pending():
    assert is_pending_kernel_boot("7.2.14-1", []) is False


def test_a_running_kernel_newer_than_the_installed_one_is_not_pending():
    """A downgrade leaves the newer kernel running; nothing to reboot into."""
    assert is_pending_kernel_boot("7.2.16-1", ["7.2.15-1"]) is False


# --- the reader and the check ---


def test_the_reader_reports_running_and_installed(monkeypatch):
    _run(monkeypatch)

    versions = collector.kernel_versions()

    assert versions["running"] == "7.2.14-1-omarchy"
    assert versions["installed"] == ["7.2.15-1"]


def test_the_reader_ignores_kernel_adjacent_packages(monkeypatch):
    """linux-firmware and linux-headers are not kernels and carry no version."""
    _run(monkeypatch, packages=(
        "linux-firmware 20260101-1\n"
        "linux-firmware-amd 20260101-1\n"
        "linux-firmware-whence 20260101-1\n"
        "linux-api-headers 7.2.15-1\n"
        "linux-omarchy-headers 7.2.15-1\n"
        "linux-omarchy 7.2.15-1\n"
    ))

    assert collector.kernel_versions()["installed"] == ["7.2.15-1"]


def test_the_reader_finds_no_kernel_on_a_non_arch_host(monkeypatch):
    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["uname", "-r"]:
            return _Result("6.1.0-1\n")
        return _Result("", 1)          # pacman missing

    monkeypatch.setattr(collector.subprocess, "run", fake_run)

    versions = collector.kernel_versions()

    assert versions["installed"] == []


def test_a_host_with_no_pacman_is_unknown(monkeypatch):
    def boom(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(collector.subprocess, "run", boom)

    assert collector.kernel_versions() is None


def test_a_pending_kernel_is_a_warning():
    findings = kernel_reboot_check(
        {"running": "7.2.14-1-omarchy", "installed": ["7.2.15-1"]}
    )

    assert [f.check for f in findings] == ["kernel.pending_reboot"]
    assert findings[0].severity.value == "warning"
    assert "7.2.14" in findings[0].message and "7.2.15" in findings[0].message


def test_an_up_to_date_kernel_is_no_finding():
    assert kernel_reboot_check(
        {"running": "7.2.15-1-omarchy", "installed": ["7.2.15-1"]}
    ) == []


def test_a_host_with_no_kernel_package_is_no_finding():
    """A non-Arch host, or one with no kernel package, is not a finding."""
    assert kernel_reboot_check({"running": "6.1.0-1", "installed": []}) == []


def test_an_unknown_state_is_not_a_finding():
    assert kernel_reboot_check(None) == []
