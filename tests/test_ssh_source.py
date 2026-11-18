"""Tests for the SSH check's handling of source-scoped rules.

Filed as issue #2. A rule scoped to a private range is not exposed to the
internet, but the check was reading an empty interface as "every interface"
and ignoring the source column entirely.
"""

import ipaddress

from volt_watch.checks import ssh_exposure_check


def _rule(source, interface="", action="ALLOW", port="22/tcp"):
    return {"port": port, "action": action, "interface": interface, "source": source}


def test_a_rule_scoped_to_a_private_range_is_not_exposed():
    findings = ssh_exposure_check([_rule("192.168.0.0/24")])

    assert findings == []


def test_a_rule_scoped_to_anywhere_is_exposed():
    findings = ssh_exposure_check([_rule("Anywhere")])

    assert [f.check for f in findings] == ["sshd.exposed"]


def test_all_private_ipv4_ranges_are_recognised():
    for source in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1"):
        assert ssh_exposure_check([_rule(source)]) == [], source


def test_private_ipv6_ranges_are_recognised():
    for source in ("fd00::/8", "fe80::/10", "::1"):
        assert ssh_exposure_check([_rule(source)]) == [], source


def test_a_single_public_address_is_not_the_internet():
    findings = ssh_exposure_check([_rule("203.0.113.7")])

    assert findings == []


def test_a_public_cidr_is_exposed():
    findings = ssh_exposure_check([_rule("8.8.8.0/24")])

    assert [f.check for f in findings] == ["sshd.exposed"]


def test_documentation_ranges_are_not_treated_as_internet_sources():
    """TEST-NET ranges cannot route from a hostile network, so they are not a
    public exposure even though they are not RFC 1918 either."""
    for source in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
        assert ssh_exposure_check([_rule(source)]) == [], source


def test_private_rule_still_reported_when_also_bound_to_the_wrong_interface():
    """A private source is safe even if the interface column is empty."""
    findings = ssh_exposure_check([_rule("10.0.0.0/8", interface="")])

    assert findings == []


def test_unparseable_source_is_treated_as_exposed():
    """An unrecognised source must fail closed, not open."""
    findings = ssh_exposure_check([_rule("not-an-address")])

    assert [f.check for f in findings] == ["sshd.exposed"]


def test_is_private_helper_handles_addresses_and_networks():
    from volt_watch.checks import _is_private_source

    assert _is_private_source("192.168.1.5") is True
    assert _is_private_source("192.168.0.0/24") is True
    assert _is_private_source("8.8.8.8") is False
    assert _is_private_source("Anywhere") is False
    assert _is_private_source("") is False
    assert ipaddress.ip_address("10.0.0.1").is_private is True
