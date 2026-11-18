"""Tests for the Tailscale mesh check."""

from volt_watch.checks import tailscale_check


def _status(**overrides):
    """Build a tailscale status payload with sensible defaults.

    Keyword arguments override top-level payload keys, so a test can set
    ``BackendState`` without it landing inside the ``Self`` node.
    """
    self_node = {
        "HostName": "omarchy-mini",
        "DNSName": "omarchy-mini.tailb1169f.ts.net.",
        "OS": "linux",
        "Online": True,
        "TailscaleIPs": ["100.71.164.78"],
        "KeyExpiry": "2027-05-16T21:43:37Z",
        "LastSeen": "2026-11-18T01:20:00Z",
        "RxBytes": 100,
        "TxBytes": 50,
    }
    payload = {"Self": self_node, "Health": [], "BackendState": "Running"}
    payload.update(overrides)
    return payload


def test_no_findings_when_the_node_is_healthy():
    findings = tailscale_check(_status())

    assert findings == []


def test_reports_backend_not_running():
    findings = tailscale_check(_status(BackendState="NeedsLogin"))

    assert [f.check for f in findings] == ["tailscale.backend"]
    assert findings[0].severity.value == "critical"
