# volt-watch

Read-only health and safety auditor for a **Tailscale-managed Linux host**.

It answers one question: *is this machine reachable, patched, and safe, and
will it come back by itself after a power cut?* It reads systemd, the
Tailscale mesh, the host firewall, and the volatile power-restore register on
Intel Macs, then reports findings with a remedy for each. It never changes
system state.

```console
$ volt-watch
$ echo $?
0
```

## Why this exists

A machine you reach over a mesh VPN has a specific set of ways to become
unreachable or exposed:

- **SSH open to the world** instead of only to the tailnet — the single most
  common way a home server gets compromised.
- **Tailscale logged out** — the node silently drops off the tailnet and every
  remote session dies with it.
- **Auto power-on disabled** — on Intel Macs the "power on when AC returns"
  bit lives in a chipset register the firmware clears on every power cycle, so
  a machine that loses power stays dark until someone presses the button.
- **A boot unit that should rewrite that register but isn't enabled** — the
  register is volatile, so the fix only holds if something reapplies it.

Each of these is invisible from the desktop and obvious in hindsight.

## Install

```bash
pip install volt-watch          # or: pipx install volt-watch
```

Needs Python 3.9+. Reads `tailscale`, `ufw`, `setpci` and `systemctl` from the
host; a missing tool is treated as "not applicable" rather than as an error.

## Usage

```console
$ volt-watch                     # plain report
$ volt-watch --json              # machine-readable
$ volt-watch --quiet             # no output; exit code only
$ volt-watch; echo $?            # 0 = clean, 1 = warnings or worse
```

Exit codes: `0` clean (or only `info`), `1` at least one warning or critical.
`info` findings never change the exit code, so the tool is usable as a
monitoring check.

## Checks

| Check | Severity | Meaning |
|---|---|---|
| `sshd.exposed` | critical | Port 22 is allowed on every interface, including the public one |
| `sshd.unrestricted` | warning | Nothing restricts port 22 and the firewall default allows incoming |
| `tailscale.backend` | critical | Backend state is `NeedsLogin`, `Stopped`, `NoState` or `Starting` |
| `power.restore_disabled` | critical | Chipset is set to stay off when power returns |
| `power.register_unreadable` | warning | `setpci` reported `0xff` — an access failure, not a value |
| `power.register_missing` | warning | No readable register (not an Intel Mac, or no LPC device) |
| `power.unit_disabled` | warning | The boot unit that restores auto power-on is not enabled |

## What it deliberately does not do

- **It does not fix anything.** Every finding carries a remedy string; applying
  it is a human decision.
- **It does not expose a service.** No listener, no agent, no remote API. It
  runs, prints, exits.
- **It does not read secrets.** It inspects configuration and state, never
  credentials.

## Running it on a schedule

A systemd timer is the intended deployment:

```ini
# ~/.config/systemd/user/volt-watch.timer
[Unit]
Description=Run volt-watch daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# ~/.config/systemd/user/volt-watch.service
[Unit]
Description=volt-watch audit

[Service]
Type=oneshot
ExecStart=/usr/local/bin/volt-watch
```

Note that the power-register check needs root to read the PCI config space.
Run it as root from a system unit if you want that check to be authoritative;
unprivileged, it reports `power.register_unreadable` instead of guessing.

## Development

Tests are the specification. Every behaviour was written as a failing test
first.

```bash
python -m pytest tests/ -q
```

## License

MIT — see [LICENSE](LICENSE).
