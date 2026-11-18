"""Regression test for the unreadable-register sentinel.

This test exists because the auditor reported a false critical finding on the
host it was developed on: `setpci` prints 0xff when it cannot open the PCI
config space, and the check read that as a register value with bit 0 set.
"""

from volt_watch.checks import power_restore_check


def test_unreadable_register_is_not_reported_as_restore_disabled():
    findings = power_restore_check({"register": 0xFF, "present": True})

    assert [f.check for f in findings] == ["power.register_unreadable"]
    assert findings[0].severity.value == "warning"


def test_a_real_value_with_bit_zero_set_is_still_critical():
    findings = power_restore_check({"register": 0x09, "present": True})

    assert [f.check for f in findings] == ["power.restore_disabled"]
    assert findings[0].severity.value == "critical"
