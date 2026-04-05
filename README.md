# domain-monitor 🔍

A lightweight, dependency-minimal tool that watches a domain for externally observable changes and notifies you when anything shifts.

## Installation

### From Source
```bash
git clone <repository-url>
cd domain-monitor
pip install -e .
```

### From Distributable Files
Download the `.whl` or `.tar.gz` file and install:
```bash
pip install domain_monitor-0.1.0.tar.gz
# or
pip install domain_monitor-0.1.0-py3-none-any.whl
```

After installation, use `domain-monitor` instead of `python domain_monitor.py`.

## Who is it for?

| User | Use-case |
|---|---|
| **Buyer** | Watching an expiring domain — get alerted as the WHOIS expiry approaches and as the domain status changes (e.g. `redemptionPeriod` → `pendingDelete` → gone) |
| **Owner** | Get alerted the moment your DNS records, WHOIS data, or SSL certificate changes unexpectedly |

## What does it monitor?

| Scope | What's checked |
|---|---|
| `whois` | Registrar, status flags, creation / expiry / updated dates, nameservers (via **RDAP** first, raw WHOIS fallback) |
| `dns` | A, AAAA, MX, NS, TXT, CAA, SOA records + DMARC (`_dmarc.domain`) |
| `ssl` | Certificate issuer, subject CN, SANs, expiry date |

## Notification channels (both free, no third parties)

| Channel | How to use | Credentials needed |
|---|---|---|
| **Email** | `--notify-email you@example.com` | SMTP env vars (App Password for Gmail) |
| **macOS notification** | `--notify-macos` | None — uses `osascript` built into macOS |

On GitHub Actions the macOS notification doesn't apply (Linux runners), so email is recommended there.

## Quick start

```bash
# Install
pip install -e .

# First run — save baseline state (no notification)
domain-monitor --domain example.com

# Daily check with macOS notification and 30-day expiry warning
domain-monitor --domain example.com --notify-macos --warn-days 30

# Full check with email notification
export SMTP_USER="you@gmail.com"
export SMTP_PASSWORD="your-app-password"
domain-monitor --domain example.com --notify-email you@example.com
```

See [SETUP.md](SETUP.md) for full setup instructions including crontab and GitHub Actions.

## Why RDAP instead of WHOIS?

RDAP (RFC 7483) is the IANA-standardised replacement for legacy WHOIS. It returns structured JSON rather than free-form text, is more reliable across TLDs, and is rate-limited per registrar rather than globally. This tool tries RDAP first via the IANA bootstrap registry (`data.iana.org/rdap/dns.json`) and falls back to raw WHOIS only when RDAP isn't available for a given TLD.

## State storage

Each domain's baseline snapshot is stored as a JSON file in the `state/` directory. On GitHub Actions the bot commits state back to the repository after each run — the commit message contains `[skip ci]` to prevent a recursive trigger.

## GitHub Actions

This repository’s workflow is configured as a manual trigger by default. The workflow file includes a commented-out `schedule:` block in `.github/workflows/monitor.yml`; uncomment the cron entry to enable daily scheduled runs.

Required GitHub Actions configuration:

- `DOMAIN`
- `NOTIFY_EMAIL`
- `SCOPE`
- `WARN_DAYS`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`

For local usage and installation options, keep following the instructions in this README and `SETUP.md`.

