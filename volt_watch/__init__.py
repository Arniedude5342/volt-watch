"""volt-watch: health and safety collector for a Tailscale-managed Linux host.

The package reads the machine's own state (systemd units, the Tailscale mesh,
the volatile power-restore register, package freshness) and reports findings.
It never changes system state: it is a read-only auditor.
"""

__version__ = "0.1.0"
