"""Certificate URL validation and participant-scoped download redirects."""

from __future__ import annotations

import os
import re
import urllib.parse


DEFAULT_ALLOWED_HOSTS = {
    "drive.google.com",
    "docs.google.com",
    "drive.usercontent.google.com",
    "googleusercontent.com",
    "docs.googleusercontent.com",
}


def allowed_hosts() -> set[str]:
    configured = os.environ.get("CERTIFICATE_ALLOWED_HOSTS", "").strip()
    if not configured:
        return set(DEFAULT_ALLOWED_HOSTS)
    return {host.strip().lower().lstrip(".") for host in configured.split(",") if host.strip()}


def host_is_allowed(host: str | None, hosts: set[str] | None = None) -> bool:
    if not host:
        return False
    host = host.rstrip(".").lower()
    for allowed in hosts or allowed_hosts():
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def safe_certificate_url(value: object, hosts: set[str] | None = None) -> bool:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return False
    try:
        parsed = urllib.parse.urlsplit(value.strip())
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.lower() == "https"
        and not parsed.username
        and not parsed.password
        and parsed.hostname is not None
        and host_is_allowed(parsed.hostname, hosts)
        and port in (None, 443)
        and not parsed.fragment
    )


def browser_download_url(value: str) -> str:
    """Return a provider download link after verifying the stored HTTPS allowlist."""
    if not safe_certificate_url(value):
        raise ValueError("Certificate URL is not on the HTTPS allowlist")
    parsed = urllib.parse.urlsplit(value)
    host = (parsed.hostname or "").lower()
    path = parsed.path
    target = value
    if host == "drive.google.com":
        match = re.search(r"/file/d/([A-Za-z0-9_-]+)", path)
        file_id = match.group(1) if match else urllib.parse.parse_qs(parsed.query).get("id", [None])[0]
        if file_id:
            target = "https://drive.google.com/uc?" + urllib.parse.urlencode(
                {"export": "download", "id": file_id}
            )
    elif host == "docs.google.com":
        match = re.search(r"/document/d/([A-Za-z0-9_-]+)", path)
        if match:
            target = f"https://docs.google.com/document/d/{match.group(1)}/export?format=pdf"
    if not safe_certificate_url(target):
        raise ValueError("Certificate download link is not on the HTTPS allowlist")
    return target
