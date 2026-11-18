"""Reading real host state.

Every reader is a thin wrapper over one command and returns plain data, or
``None`` when the thing it asked about is not there. A missing tool is a normal
answer, not an exception: the auditor runs on hosts where Tailscale or the
Mac-specific register does not exist.
"""

import json
import subprocess

# The volatile register and device path for Intel Mac mini power restore.
LPC_ADDRESS = "00:1f.0"
LPC_REGISTER = "0xa4.b"
POWER_UNIT = "mac-mini-power-restore.service"


def _run(cmd: list) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def tailscale_status() -> dict | None:
    """Return the parsed ``tailscale status --json`` payload, or None."""
    try:
        done = _run(["tailscale", "status", "--json"])
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        return None


def ufw_rules() -> list:
    """Parse ``ufw status verbose`` into rule dicts."""
    try:
        done = _run(["ufw", "status", "verbose"])
    except (OSError, subprocess.SubprocessError):
        return []
    if done.returncode != 0:
        return []

    rules = []
    in_table = False
    for line in done.stdout.splitlines():
        if line.startswith("To "):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.strip():
            break
        # The dashed separator row under the header.
        if line.lstrip().startswith("--"):
            continue

        # The row is "<port> [on <iface>] <ACTION> [IN] <source>". Split the
        # whole line into columns and read them positionally: the interface
        # qualifier, when present, occupies the second column.
        columns = line.split()
        if len(columns) < 2:
            continue

        port = columns[0]
        index = 1
        interface = ""
        if columns[index] == "on" and len(columns) > index + 1:
            interface = columns[index + 1]
            index += 2

        action = columns[index] if len(columns) > index else ""
        source = " ".join(columns[index + 1:]) if len(columns) > index + 1 else ""
        # ufw writes the direction as its own column ("ALLOW IN"); it is not
        # part of the source.
        if source.startswith("IN "):
            source = source[3:]
        elif source == "IN":
            source = ""

        rules.append(
            {
                "port": port,
                "action": action,
                "interface": interface,
                "source": source.strip(),
            }
        )
    return rules


def ufw_default_incoming() -> str:
    """Return the firewall's default incoming policy: ``allow`` or ``deny``."""
    try:
        done = _run(["ufw", "status", "verbose"])
    except (OSError, subprocess.SubprocessError):
        return "deny"
    if done.returncode != 0:
        return "deny"

    for line in done.stdout.splitlines():
        if line.startswith("Default:"):
            match = line.split("incoming)", 1)
            policy = match[0].rsplit(":", 1)[-1].strip()
            return policy if policy in ("allow", "deny") else "deny"
    return "deny"


def power_restore_state() -> dict:
    """Read the power-restore register and the boot unit that rewrites it."""
    state = {"present": False, "register": None, "unit_enabled": None}

    try:
        done = _run(["setpci", "-s", LPC_ADDRESS, LPC_REGISTER])
    except (OSError, subprocess.SubprocessError):
        return state

    if done.returncode == 0 and done.stdout.strip():
        state["present"] = True
        try:
            state["register"] = int(done.stdout.strip(), 16)
        except ValueError:
            state["register"] = None

    state["unit_enabled"] = unit_enabled(POWER_UNIT)
    return state


def unit_enabled(name: str) -> bool | None:
    """Return whether a systemd unit is enabled, or None if systemctl fails."""
    try:
        done = _run(["systemctl", "is-enabled", name])
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return False
    return done.stdout.strip() == "enabled"
