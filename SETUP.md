# Setup Guide

## 1. Prerequisites

- Python 3.6 or later
- macOS (for local macOS notifications) or any Linux/macOS machine for email notifications

## 2. Install

### Option A: From Distributable Package (Recommended)

```bash
# Download domain_monitor-0.1.0-py3-none-any.whl or domain_monitor-0.1.0.tar.gz

# Install using pip
pip install domain_monitor-0.1.0-py3-none-any.whl
# or
pip install domain_monitor-0.1.0.tar.gz
```

### Option B: From Source (Development)

```bash
# Clone or download the repository
cd /path/to/domain-monitor

# Create and activate a virtual environment (optional but recommended)
python3 -m venv .venv
source .venv/bin/activate      # macOS/Linux
# .venv\Scripts\activate       # Windows

# Install in editable mode
pip install -e .
```

After installation, the `domain-monitor` command is available globally.

## 3. First run — save a baseline

The first time you run the tool no notification is sent; it just saves the current state so future runs have something to compare against.

```bash
domain-monitor --domain example.com
```

A file will be created in your platform-specific state directory:
- **macOS**: `~/Library/Application Support/domain-monitor/example.com.json`
- **Linux**: `~/.local/share/domain-monitor/example.com.json` (respects `$XDG_STATE_HOME`)
- **Windows**: `%LOCALAPPDATA%/domain-monitor/example.com.json`

Subsequent runs compare against this baseline.

## 4. CLI reference

```
domain-monitor [options]

Required:
  --domain DOMAIN       Domain name to monitor (e.g. example.com)

Optional:
  --scope SCOPE         Comma-separated checks: whois, dns, ssl  (default: all)
  --warn-days N         Also alert when expiry is within N days  (default: 0, disabled)
  --notify-email EMAIL  Send email notification to this address
  --notify-macos        Send macOS Notification Center alert (no credentials)
  --state-dir DIR       Directory for state files               (default: platform-specific)
  --force               Notify even if nothing changed (useful for testing)
  --verbose / -v        Enable debug logging
```

### Examples

```bash
# Watch DNS only
domain-monitor --domain example.com --scope dns

# Watch a domain you want to buy — WHOIS + SSL, warn at 14 days, macOS popup
domain-monitor --domain example.com --scope whois,ssl \
    --warn-days 14 --notify-macos

# Full monitoring with email
domain-monitor --domain example.com \
    --notify-email you@example.com --warn-days 30

# Test notifications without waiting for a real change
domain-monitor --domain example.com --force --notify-macos

# Use a custom state directory
domain-monitor --domain example.com --state-dir /path/to/custom/state
```

## 5. Email setup

Email is sent via SMTP. The following environment variables are supported:

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | `smtp.gmail.com` | SMTP server hostname |
| `SMTP_PORT` | `465` | SMTP port (465 = SSL, 587 = STARTTLS) |
| `SMTP_USER` | *(required)* | Sender email address |
| `SMTP_PASSWORD` | *(required)* | Sender password or App Password |

### Gmail App Password (recommended)

Using your real Gmail password doesn't work with SMTP when 2FA is enabled. Use an **App Password** instead:

1. Go to [myaccount.google.com/security](https://myaccount.google.com/security)
2. Under "How you sign in to Google", click **2-Step Verification** (enable it if not already)
3. Scroll to the bottom → **App passwords**
4. Create a new app password (name it "domain-monitor")
5. Copy the 16-character password

```bash
export SMTP_USER="you@gmail.com"
export SMTP_PASSWORD="abcd efgh ijkl mnop"   # the 16-char app password
```

### iCloud Mail

```bash
export SMTP_HOST="smtp.mail.me.com"
export SMTP_PORT="587"
export SMTP_USER="you@icloud.com"
export SMTP_PASSWORD="your-app-specific-password"
```

Generate an iCloud app-specific password at [appleid.apple.com](https://appleid.apple.com) → Sign-In and Security → App-Specific Passwords.

## 6. macOS notifications

macOS notifications use `osascript` which is built into every Mac. No install, no credentials, no accounts.

```bash
domain-monitor --domain example.com --notify-macos
```

To allow notifications, go to **System Settings → Notifications → Script Editor** (or Terminal, depending on how you run the script) and enable notifications.

## 7. Running on a schedule — crontab

```bash
# Edit your crontab
crontab -e
```

Add one of these entries (adjust paths):

```cron
# Check example.com every day at 07:30, macOS notification
30 7 * * * domain-monitor --domain example.com --notify-macos --warn-days 30 >> /tmp/domain_monitor.log 2>&1

# Check example.com every day at 07:30, email notification
30 7 * * * SMTP_USER=you@gmail.com SMTP_PASSWORD=abcdefghijklmnop domain-monitor --domain example.com --notify-email you@example.com --warn-days 30 >> /tmp/domain_monitor.log 2>&1
```

> **Tip**: macOS may put `Terminal` to sleep and suppress cron on idle Macs. For reliable scheduling consider using **launchd** instead, or just use GitHub Actions (below).

### launchd example (macOS, more reliable than cron)

Create `~/Library/LaunchAgents/com.domain-monitor.example.com.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.domain-monitor.example.com</string>

  <key>ProgramArguments</key>
  <array>
    <string>domain-monitor</string>
    <string>--domain</string>        <string>example.com</string>
    <string>--notify-macos</string>
    <string>--warn-days</string>     <string>30</string>
  </array>

  <key>EnvironmentVariables</key>
  <dict>
    <key>SMTP_USER</key>     <string>you@gmail.com</string>
    <key>SMTP_PASSWORD</key> <string>abcdefghijklmnop</string>
  </dict>

  <!-- Run daily at 07:30 -->
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>   <integer>7</integer>
    <key>Minute</key> <integer>30</integer>
  </dict>

  <key>StandardOutPath</key> <string>/tmp/domain-monitor.log</string>
  <key>StandardErrorPath</key><string>/tmp/domain-monitor.log</string>
</dict>
</plist>
```

Load it:
```bash
launchctl load ~/Library/LaunchAgents/com.domain-monitor.example.com.plist
```

## 8. GitHub Actions setup

This is the recommended option for reliability — GitHub runs it in the cloud so your Mac doesn't need to be on.

This public repository is configured for manual workflow execution by default. The `.github/workflows/monitor.yml` file includes a commented-out `schedule:` block. Uncomment that block and commit the workflow file to enable daily scheduled runs.

### Step 1: Place the workflow file

Add `.github/workflows/monitor.yml` to the repository.

### Step 2: Set secrets (Settings → Secrets and variables → Actions → Secrets)

| Secret | Value |
|---|---|
| `SMTP_USER` | Your email address |
| `SMTP_PASSWORD` | Your App Password |

### Step 3: Set variables (Settings → Secrets and variables → Actions → Variables)

| Variable | Example | Notes |
|---|---|---|
| `DOMAIN` | `example.com` | Space-separated for multiple: `"a.com b.com"` |
| `NOTIFY_EMAIL` | `you@example.com` | Where to send alerts |
| `SCOPE` | `all` | `whois`, `dns`, `ssl`, or `all` |
| `WARN_DAYS` | `30` | Alert when expiry is within this many days |
| `SMTP_HOST` | `smtp.gmail.com` | Leave blank to use Gmail default |
| `SMTP_PORT` | `465` | Leave blank to use default |

### Step 4: Run the workflow

Go to **Actions** → **Domain Monitor** → click **Run workflow**. To enable scheduled automation, uncomment the `schedule:` / `cron:` block in `.github/workflows/monitor.yml`, commit, and push.

### How state is stored on GitHub Actions

After each run the bot commits the updated `state/*.json` files back to the repository with the message `chore: update domain monitor state [skip ci]`. The `[skip ci]` tag prevents the commit from triggering another workflow run.

## 9. Monitoring multiple domains

Each domain gets its own state file in your platform-specific state directory. On the command line, just run the script once per domain (cron handles this naturally):

```cron
30 7 * * * domain-monitor --domain example.com --notify-macos --warn-days 30 >> /tmp/monitor.log 2>&1
30 7 * * * domain-monitor --domain another.com --notify-macos --warn-days 30 >> /tmp/monitor.log 2>&1
```

On GitHub Actions, set `DOMAIN` to a space-separated list and the workflow loops over each one automatically.
