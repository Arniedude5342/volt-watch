"""Tests for #38: a full disk is invisible to the auditor.

The failure mode that takes a host down fastest after a network problem is a
full filesystem, and ``df -h`` showing 99% used is not something the rest of
the tool catches. Both the byte and the inode side matter: a host can have
terabytes free and still be dead because a directory of small files exhausted
its inodes.
"""

from volt_watch import collector
from volt_watch.checks import disk_space_check


class _Statvfs:
    """The subset of os.statvfs the reader uses, built from percentages.

    ``blocks_used_pct`` and ``inodes_used_pct`` are the two numbers the check
    reads; everything else is derived so the reader's arithmetic is exercised
    rather than mocked away.
    """

    def __init__(self, blocks_used_pct: float, inodes_used_pct: float,
                 block_size: int = 4096) -> None:
        self.f_bsize = block_size
        self.f_frsize = block_size
        self.f_blocks = 1_000_000
        self.f_bfree = int(self.f_blocks * (1 - blocks_used_pct / 100))
        self.f_bavail = self.f_bfree
        self.f_files = 1_000_000
        self.f_ffree = int(self.f_files * (1 - inodes_used_pct / 100))


def _patch_disk(monkeypatch, blocks_used_pct: float, inodes_used_pct: float):
    monkeypatch.setattr(
        collector.os, "statvfs",
        lambda path: _Statvfs(blocks_used_pct, inodes_used_pct),
    )


def test_the_reader_reports_both_bytes_and_inodes(monkeypatch):
    _patch_disk(monkeypatch, 97.0, 4.0)

    usage = collector.disk_usage()

    assert usage["percent_used"] == 97.0
    assert usage["inode_percent_used"] == 4.0
    # Free bytes are part of the evidence: a percentage alone does not say
    # whether 5% of a 40 GB disk or 5% of a 2 TB disk is left.
    assert usage["free"] > 0


def test_the_reader_returns_none_only_when_statvfs_raises(monkeypatch):
    def boom(path):
        raise OSError(path)

    monkeypatch.setattr(collector.os, "statvfs", boom)

    assert collector.disk_usage() is None


def test_ninety_percent_is_a_warning(monkeypatch):
    _patch_disk(monkeypatch, 90.0, 1.0)

    findings = disk_space_check(collector.disk_usage())

    assert [f.check for f in findings] == ["disk.space_low"]
    assert findings[0].severity.value == "warning"


def test_ninety_five_percent_is_critical(monkeypatch):
    _patch_disk(monkeypatch, 95.0, 1.0)

    findings = disk_space_check(collector.disk_usage())

    assert findings[0].severity.value == "critical"


def test_the_byte_boundaries(monkeypatch):
    """89.9% is fine, 90% warns, 94.9% still warns and 95% is critical."""
    for pct, expected in ((89.9, 0), (90.0, 1), (94.9, 1), (95.0, 1)):
        _patch_disk(monkeypatch, pct, 0.0)
        findings = disk_space_check(collector.disk_usage())
        assert len(findings) == expected, f"{pct}% should give {expected}"


def test_inodes_run_their_own_threshold(monkeypatch):
    """A disk with room to spare but no inodes left is still dead."""
    _patch_disk(monkeypatch, 50.0, 99.5)

    findings = disk_space_check(collector.disk_usage())

    assert findings[0].severity.value == "critical"
    assert "inode" in findings[0].message.lower()


def test_an_unknown_disk_is_not_a_finding():
    assert disk_space_check(None) == []


def test_a_healthy_disk_is_no_finding(monkeypatch):
    _patch_disk(monkeypatch, 42.0, 3.0)

    assert disk_space_check(collector.disk_usage()) == []
