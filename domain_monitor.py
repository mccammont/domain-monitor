#!/usr/bin/env python3
"""
domain_monitor.py — Watch a domain for WHOIS, DNS, and SSL changes.

Notification channels (all free, no third-party services):
  --notify-email   SMTP email (configure via SMTP_* env vars)
  --notify-macos   macOS native notification (osascript, zero dependencies)
"""

import argparse
import functools
import json
import logging
import os
import re
import smtplib
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, cast, Dict, List, Optional, Tuple

import dns.resolver
from dns.exception import DNSException
import requests

WHOIS_MODULE: Any = None
try:
    import whois as WHOIS_MODULE  # type: ignore
    from whois import WhoisError  # type: ignore
except ImportError:  # type: ignore

    class WhoisError(Exception):
        """Fallback exception type when python-whois is unavailable."""


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("domain_monitor")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_str(value: Any) -> str:
    """Convert a value (possibly a list) to a stable string."""
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value) if value is not None else ""


# ---------------------------------------------------------------------------
# RDAP — structured WHOIS replacement (RFC 7483)
# ---------------------------------------------------------------------------

_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


@functools.lru_cache(maxsize=1)
def _get_rdap_bootstrap() -> Optional[Dict[str, Any]]:
    try:
        resp = requests.get(_RDAP_BOOTSTRAP_URL, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError) as exc:
        log.warning("Failed to fetch RDAP bootstrap: %s", exc)
        return None


def _get_rdap_base_url(tld: str) -> Optional[str]:
    bootstrap = _get_rdap_bootstrap()
    if not bootstrap:
        return None

    for entry in bootstrap.get("services", []):
        tlds, urls = entry[0], entry[1]
        if tld.lower() in [t.lower() for t in tlds]:
            return urls[0].rstrip("/")
    return None


def get_rdap_data(domain: str) -> Dict[str, Any]:
    """Fetch WHOIS-equivalent data via RDAP (structured JSON, RFC 7483)."""
    tld = domain.rsplit(".", 1)[-1]
    base_url = _get_rdap_base_url(tld)
    if not base_url:
        log.debug("No RDAP base URL for TLD '%s'", tld)
        return {}

    try:
        resp = requests.get(f"{base_url}/domain/{domain}", timeout=10)
        if resp.status_code == 404:
            log.info("RDAP: domain %s not found (may be unregistered)", domain)
            return {"status": "not_found"}
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        log.warning("RDAP lookup failed for %s: %s", domain, exc)
        return {}

    result: Dict[str, Any] = {
        "source": "rdap",
        "status": data.get("status", []),
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": sorted(
            [
                ns["ldhName"].lower()
                for ns in data.get("nameservers", [])
                if "ldhName" in ns
            ]
        ),
    }

    # Parse events (creation, expiration, last changed)
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action == "registration":
            result["creation_date"] = date[:10] if date else None
        elif action == "expiration":
            result["expiration_date"] = date[:10] if date else None
        elif action == "last changed":
            result["updated_date"] = date[:10] if date else None

    # Parse registrar from entities
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        result["registrar"] = item[3]
                        break

    return result


def get_whois_fallback(domain: str) -> Dict[str, Any]:
    """Fallback WHOIS via python-whois when RDAP is unavailable."""
    if WHOIS_MODULE is None:
        log.warning("python-whois not installed; skipping WHOIS fallback")
        return {}

    try:
        w = cast(Any, WHOIS_MODULE.whois(domain))
        return {
            "source": "whois",
            "status": (
                w.status
                if isinstance(w.status, list)
                else [w.status] if w.status else []
            ),
            "registrar": w.registrar,
            "creation_date": (
                _safe_str(w.creation_date)[:10] if w.creation_date else None
            ),
            "expiration_date": (
                _safe_str(w.expiration_date)[:10] if w.expiration_date else None
            ),
            "updated_date": _safe_str(w.updated_date)[:10] if w.updated_date else None,
            "name_servers": (
                sorted([ns.lower() for ns in w.name_servers]) if w.name_servers else []
            ),
        }
    except WhoisError as exc:
        log.warning("python-whois fallback failed: %s", exc)
        return {}
    except OSError as exc:
        log.warning("python-whois fallback failed: %s", exc)
        return {}


def get_registration_data(domain: str) -> Dict[str, Any]:
    """Try RDAP first, fall back to raw WHOIS."""
    data = get_rdap_data(domain)
    if data:
        return data
    log.info("Falling back to raw WHOIS for %s", domain)
    return get_whois_fallback(domain)


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"]


def get_dns_records(domain: str) -> Dict[str, List[str]]:
    """Fetch standard DNS records plus DMARC TXT."""
    records: Dict[str, List[str]] = {}

    for rtype in DNS_RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = sorted([rdata.to_text() for rdata in answers])
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            log.warning("Domain %s does not exist (NXDOMAIN)", domain)
            records[rtype] = []
        except DNSException as exc:
            log.debug("Error fetching %s records for %s: %s", rtype, domain, exc)
            records[rtype] = []

    # DMARC is a TXT record at a subdomain
    dmarc_host = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_host, "TXT")
        records["DMARC"] = sorted([rdata.to_text() for rdata in answers])
    except DNSException:
        records["DMARC"] = []

    return records


# ---------------------------------------------------------------------------
# SSL / TLS certificate
# ---------------------------------------------------------------------------


def _parse_ssl_cert(cert: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Normalize an SSL certificate dictionary into typed fields."""
    if cert is None:
        return {"error": "no certificate data"}

    not_after_raw = cert.get("notAfter", "")
    not_before_raw = cert.get("notBefore", "")
    try:
        not_after = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        not_before = datetime.strptime(not_before_raw, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_remaining = (not_after - datetime.now(timezone.utc)).days
    except ValueError:
        not_after = not_before = None
        days_remaining = None

    subject = cert.get("subject", [])
    issuer = cert.get("issuer", [])
    sans = [
        f"{san_type}:{san_value}"
        for san_type, san_value in cert.get("subjectAltName", [])
    ]

    return {
        "subject_cn": _extract_cert_field(subject, "commonName"),
        "issuer_o": _extract_cert_field(issuer, "organizationName"),
        "issuer_cn": _extract_cert_field(issuer, "commonName"),
        "not_before": not_before.date().isoformat() if not_before else not_before_raw,
        "not_after": not_after.date().isoformat() if not_after else not_after_raw,
        "days_remaining": days_remaining,
        "sans": sorted(sans),
        "serial_number": cert.get("serialNumber"),
    }


def get_ssl_info(domain: str, port: int = 443) -> Dict[str, Any]:
    """Connect to domain:port, retrieve TLS certificate details."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except (socket.timeout, OSError, ssl.SSLError) as exc:
        log.warning("SSL connection failed for %s:%d — %s", domain, port, exc)
        return {"error": str(exc)}

    return _parse_ssl_cert(cert)


# ---------------------------------------------------------------------------
# Collect current state
# ---------------------------------------------------------------------------


def collect_state(domain: str, scope: List[str]) -> Dict[str, Any]:
    """Collect current WHOIS, DNS, and SSL state for the domain."""
    state: Dict[str, Any] = {"collected_at": datetime.now(timezone.utc).isoformat()}

    if "whois" in scope:
        log.info("Fetching registration data (RDAP/WHOIS) for %s…", domain)
        state["whois"] = get_registration_data(domain)

    if "dns" in scope:
        log.info("Fetching DNS records for %s…", domain)
        state["dns"] = get_dns_records(domain)

    if "ssl" in scope:
        log.info("Fetching SSL certificate for %s…", domain)
        state["ssl"] = get_ssl_info(domain)

    return state


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def _flat_diff(old: Any, new: Any, path: str = "") -> List[Tuple[str, Any, Any]]:
    """Recursively find differences between two nested dicts/lists/scalars."""
    changes = []

    # Skip internal metadata keys that legitimately change every run
    skip_keys = {"collected_at", "source", "days_remaining"}

    if isinstance(old, dict) and isinstance(new, dict):
        all_keys = set(old) | set(new)
        for k in sorted(all_keys):
            if k in skip_keys:
                continue
            child_path = f"{path}.{k}" if path else k
            changes.extend(_flat_diff(old.get(k), new.get(k), child_path))
    elif old != new:
        changes.append((path, old, new))

    return changes


def compute_diff(previous: Dict, current: Dict) -> List[Tuple[str, Any, Any]]:
    """Return a flat list of differences between previous and current state."""
    return _flat_diff(previous, current)


# ---------------------------------------------------------------------------
# Expiry warnings
# ---------------------------------------------------------------------------


def _expiry_warnings(state: Dict, warn_days: int, domain: str) -> List[str]:
    warnings = []

    # WHOIS expiration
    expiry_str = state.get("whois", {}).get("expiration_date")
    if expiry_str:
        try:
            expiry = datetime.fromisoformat(expiry_str).replace(tzinfo=timezone.utc)
            days = (expiry - datetime.now(timezone.utc)).days
            if 0 <= days <= warn_days:
                warnings.append(
                    f"⚠️  WHOIS expiration for {domain} is in {days} day(s) ({expiry_str})"
                )
            elif days < 0:
                warnings.append(
                    f"🔴  Domain {domain} appears to have EXPIRED {abs(days)} day(s) "
                    f"ago ({expiry_str})"
                )
        except ValueError:
            pass

    # SSL expiration
    ssl_days = state.get("ssl", {}).get("days_remaining")
    ssl_expiry = state.get("ssl", {}).get("not_after")
    if ssl_days is not None:
        if 0 <= ssl_days <= warn_days:
            warnings.append(
                f"⚠️  SSL certificate for {domain} expires in {ssl_days} day(s) ({ssl_expiry})"
            )
        elif ssl_days < 0:
            warnings.append(
                f"🔴  SSL certificate for {domain} EXPIRED {abs(ssl_days)} day(s) ago ({ssl_expiry})"
            )

    return warnings


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


def _extract_cert_field(field_list: List, key: str) -> Optional[str]:
    for item in field_list:
        for k, v in item:
            if k == key:
                return v
    return None


def notify_email(to_email: str, subject: str, body: str) -> None:
    """Send an email notification using SMTP environment credentials."""
    smtp_host = (
        os.environ.get("SMTP_HOST") or "smtp.gmail.com"
    ).strip() or "smtp.gmail.com"
    smtp_port = int((os.environ.get("SMTP_PORT") or "465").strip() or "465")
    smtp_user = os.environ.get("SMTP_USER") or os.environ.get("EMAIL_USER")
    smtp_pass = os.environ.get("SMTP_PASSWORD") or os.environ.get("EMAIL_PASSWORD")

    if not smtp_user or not smtp_pass:
        log.error(
            "Email notification requires SMTP_USER and SMTP_PASSWORD environment variables."
        )
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = to_email
    msg.attach(MIMEText(body, "plain"))

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
        log.info("Email sent to %s", to_email)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        log.error("Failed to send email: %s", exc)


def notify_macos(title: str, body: str) -> None:
    """Send a macOS Notification Center alert — no dependencies, no credentials."""
    # Truncate body to avoid dialog overflow
    safe_body = body.replace('"', "'").replace("\\", "/")[:300]
    safe_title = title.replace('"', "'")
    script = f'display notification "{safe_body}" with title "{safe_title}"'
    try:
        subprocess.run(["osascript", "-e", script], check=True, capture_output=True)
        log.info("macOS notification sent.")
    except FileNotFoundError:
        log.error("osascript not found — macOS notification only works on macOS.")
    except subprocess.CalledProcessError as exc:
        log.error("osascript error: %s", exc.stderr.decode().strip())


def dispatch_notifications(
    args: argparse.Namespace,
    subject: str,
    body: str,
) -> None:
    """Dispatch notifications via configured channels."""
    if args.notify_email:
        notify_email(args.notify_email, subject, body)
    if args.notify_macos:
        notify_macos(subject, body)


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


def _state_file_path(state_dir: str, domain: str) -> Path:
    """Return the JSON state file path for a given domain."""
    safe = re.sub(r"[^\w\-.]", "_", domain)
    return Path(state_dir) / f"{safe}.json"


def load_state(state_dir: str, domain: str) -> Optional[Dict]:
    """Load previous domain state from disk if it exists."""
    path = _state_file_path(state_dir, domain)
    if not path.exists():
        return None
    try:
        with path.open("r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("Could not read state file %s: %s", path, exc)
        return None


def save_state(state_dir: str, domain: str, state: Dict) -> None:
    """Persist the current state for a domain to disk."""
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    path = _state_file_path(state_dir, domain)
    with path.open("w") as f:
        json.dump(state, f, indent=2, default=str)
    log.info("State saved to %s", path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def build_report(
    domain: str, changes: List[Tuple], warnings: List[str]
) -> Tuple[str, str]:
    """Return (subject, body) for the notification."""
    parts = []

    if warnings:
        parts.append("EXPIRY WARNINGS\n" + "\n".join(warnings))

    if changes:
        change_lines = []
        for field, old, new in changes:
            change_lines.append(f"  {field}:\n    was: {old}\n    now: {new}")
        parts.append("CHANGES DETECTED\n" + "\n".join(change_lines))

    body = (
        f"Domain Monitor report for {domain}\nRun at: {datetime.now().isoformat()}\n\n"
    )
    body += "\n\n".join(parts)

    flags = []
    if warnings:
        flags.append("EXPIRY WARNING")
    if changes:
        flags.append("CHANGES DETECTED")
    subject = f"[domain-monitor] {domain}: {', '.join(flags)}"

    return subject, body


def parse_int_or_default(value: str) -> int:
    """Parse an integer from a string, treating empty values as zero."""
    if value is None or str(value).strip() == "":
        return 0
    try:
        return int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid int value: {value}") from exc


def parse_scope(raw: Optional[str]) -> List[str]:
    """Normalize the scope string into a list of enabled checks."""
    if raw is None or raw.strip() == "" or raw.strip().lower() == "all":
        return ["whois", "dns", "ssl"]
    parts = [p.strip().lower() for p in raw.split(",")]
    valid = {"whois", "dns", "ssl"}
    unknown = set(parts) - valid
    if unknown:
        log.warning("Unknown scope value(s) ignored: %s", unknown)
    return [p for p in parts if p in valid]


def get_default_state_dir() -> Path:
    """
    Get the default directory for storing domain state files.

    Uses platform-specific conventions for user data directories.

    Returns:
        Path: The default state directory.
    """
    if sys.platform == "darwin":  # macOS
        return Path.home() / "Library" / "Application Support" / "domain-monitor"
    if sys.platform == "win32":
        base = Path(os.getenv("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local")))
        return base / "domain-monitor"
    xdg_state = os.getenv("XDG_STATE_HOME")
    if xdg_state:
        return Path(xdg_state) / "domain-monitor"
    return Path.home() / ".local" / "share" / "domain-monitor"


def main() -> int:
    """Parse CLI arguments, run checks, and persist domain state."""
    parser = argparse.ArgumentParser(
        description="Monitor a domain for WHOIS, DNS, and SSL changes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # First run — saves baseline state
  python domain_monitor.py --domain example.com

  # Daily check with email alert
  python domain_monitor.py --domain example.com --notify-email you@example.com

  # macOS notification + expiry warning when <= 30 days remain
  python domain_monitor.py --domain example.com --notify-macos --warn-days 30

  # Watch only DNS records
  python domain_monitor.py --domain example.com --scope dns

Environment variables for email:
  SMTP_HOST       SMTP server host (default: smtp.gmail.com)
  SMTP_PORT       SMTP server port (default: 465)
  SMTP_USER       Sender email address
  SMTP_PASSWORD   Sender email password / app password
""",
    )
    parser.add_argument("--domain", required=True, help="Domain name to monitor")
    parser.add_argument(
        "--scope",
        default="all",
        help="Comma-separated list of checks: whois, dns, ssl (default: all)",
    )
    parser.add_argument(
        "--warn-days",
        type=parse_int_or_default,
        default=0,
        metavar="N",
        help="Also alert when expiry (WHOIS or SSL) is within N days",
    )
    parser.add_argument(
        "--notify-email",
        metavar="EMAIL",
        help="Send email notification to this address",
    )
    parser.add_argument(
        "--notify-macos",
        action="store_true",
        help="Send a macOS Notification Center alert (no credentials required)",
    )
    parser.add_argument(
        "--state-dir",
        default=None,
        help=(
            "Directory to store per-domain state files "
            "(default: platform-specific user data directory)"
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force notification even if no changes (useful for testing)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )

    args = parser.parse_args()

    args.state_dir = args.state_dir or str(get_default_state_dir())
    args.notify_email = (
        args.notify_email.strip()
        if args.notify_email and args.notify_email.strip()
        else None
    )

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    domain = args.domain.lower().strip()
    if not domain:
        log.error("--domain must be a non-empty domain name.")
        return 1

    scope = parse_scope(args.scope)
    if not scope:
        log.warning("Empty scope provided, defaulting to all checks.")
        scope = ["whois", "dns", "ssl"]

    log.info("Monitoring %s | scope: %s | warn-days: %d", domain, scope, args.warn_days)

    # Collect fresh data
    current_state = collect_state(domain, scope)

    # Load previous run
    previous_state = load_state(args.state_dir, domain)

    changes: List[Tuple] = []
    if previous_state:
        changes = compute_diff(previous_state, current_state)
        if changes:
            log.info("%d change(s) detected.", len(changes))
        else:
            log.info("No changes detected.")
    else:
        log.info("No previous state found — saving baseline. No notification sent.")

    # Expiry warnings (run even on first execution)
    warnings: List[str] = []
    if args.warn_days > 0:
        warnings = _expiry_warnings(current_state, args.warn_days, domain)
        for w in warnings:
            log.warning(w)

    # Notify
    if (changes or warnings or args.force) and previous_state is not None:
        subject, body = build_report(domain, changes, warnings)
        dispatch_notifications(args, subject, body)
    elif args.force and previous_state is None:
        log.info("--force has no effect on first run (no baseline to compare).")

    # Persist state
    save_state(args.state_dir, domain, current_state)

    return 0


if __name__ == "__main__":
    sys.exit(main())
