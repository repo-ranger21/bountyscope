#!/usr/bin/env python3
"""
get_nonce.py — WordPress REST API nonce extractor
BountyScope Workspace | @lucius-log

Fetches a WordPress admin page and extracts the WP REST API nonce from
inline script tags. FluentCRM injects it via wp_localize_script() as part
of several JS variable patterns. Prints the nonce to stdout so it can be
captured directly in shell scripts.

Usage:
    python3 get_nonce.py \\
        --target http://fluent-test.local \\
        --cookie "wordpress_logged_in_...=admin_session..."

    # Capture directly into a variable
    VICTIM_NONCE=$(python3 get_nonce.py --target http://fluent-test.local \\
        --cookie "$VICTIM_COOKIE")
"""

import argparse
import re
import ssl
import sys
import urllib.request
import urllib.error
from typing import Optional


# Nonce search patterns in priority order.
# WordPress nonces are 10 hex characters (0-9a-f).
# Each tuple: (label, compiled_regex)
_NONCE_PATTERNS = [
    # wpApiSettings — injected by wp-api or WP REST infrastructure
    ("wpApiSettings.nonce",      re.compile(r'wpApiSettings\s*=\s*\{[^}]*?"nonce"\s*:\s*"([0-9a-f]{10})"')),
    # WP inline REST config added by newer WP versions
    ("wp.apiFetch nonce",        re.compile(r'wp\.apiFetch\.use.*?nonce["\s:]+([0-9a-f]{10})')),
    # FluentCRM appVars (most common in FluentCRM 2.x)
    ("appVars.nonce",            re.compile(r'appVars\s*=\s*\{[^}]*?"nonce"\s*:\s*"([0-9a-f]{10})"')),
    # FluentCRM fcrm_nonce standalone variable
    ("fcrm_nonce",               re.compile(r'fcrm_nonce\s*[=:]\s*["\']([0-9a-f]{10})["\']')),
    # FluentCRM FluentCRMVars / fluentCRMAdmin
    ("FluentCRMVars.nonce",      re.compile(r'[Ff]luent[A-Za-z]*\s*=\s*\{[^}]*?"nonce"\s*:\s*"([0-9a-f]{10})"')),
    # Generic "nonce":"VALUE" anywhere in a script block (broadest fallback)
    ("generic nonce field",      re.compile(r'"nonce"\s*:\s*"([0-9a-f]{10})"')),
    # WP _wpnonce in a form (REST nonce is different, but useful as last resort)
    ("_wpnonce form field",      re.compile(r'name=["\']_wpnonce["\']\s+value=["\']([0-9a-f]{10})["\']')),
]

# Pages to try in order — stop at first successful extraction
_ADMIN_PATHS = [
    "/wp-admin/admin.php?page=fluentcrm-admin",
    "/wp-admin/",
    "/wp-admin/index.php",
]


def build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_page(url: str, cookie: str, ssl_ctx: ssl.SSLContext) -> tuple[int, str]:
    headers = {
        "Cookie": cookie,
        "User-Agent": "Mozilla/5.0 (BountyScope nonce extractor)",
        "Accept": "text/html,application/xhtml+xml",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10, context=ssl_ctx) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body
    except urllib.error.URLError as e:
        return 0, str(e.reason)


def extract_nonce(html: str, verbose: bool = False) -> Optional[str]:
    for label, pattern in _NONCE_PATTERNS:
        match = pattern.search(html)
        if match:
            nonce = match.group(1)
            if verbose:
                print(f"  [found] {label}: {nonce}", file=sys.stderr)
            return nonce
        elif verbose:
            print(f"  [miss]  {label}", file=sys.stderr)
    return None


def run(target: str, cookie: str, verbose: bool) -> Optional[str]:
    target = target.rstrip("/")
    ssl_ctx = build_ssl_context()

    for path in _ADMIN_PATHS:
        url = f"{target}{path}"
        if verbose:
            print(f"\nFetching: {url}", file=sys.stderr)

        status, html = fetch_page(url, cookie, ssl_ctx)

        if status == 0:
            print(f"[error] Connection failed: {html}", file=sys.stderr)
            continue

        if status in (401, 403):
            print(f"[error] HTTP {status} — cookie may be expired or not admin", file=sys.stderr)
            continue

        if status == 302:
            # Redirect usually means the cookie isn't accepted as admin
            print(f"[warn]  HTTP 302 on {path} — session may not have admin access", file=sys.stderr)
            continue

        if status != 200:
            print(f"[warn]  HTTP {status} on {path}, trying next path", file=sys.stderr)
            continue

        if verbose:
            print(f"  HTTP {status} — {len(html)} bytes received", file=sys.stderr)

        nonce = extract_nonce(html, verbose)
        if nonce:
            return nonce

        print(f"[warn]  No nonce found in {path}, trying next path", file=sys.stderr)

    return None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract WP REST API nonce from FluentCRM admin page",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 get_nonce.py \\
      --target http://fluent-test.local \\
      --cookie "wordpress_logged_in_...=admin_session..."

  # Capture into shell variable
  VICTIM_NONCE=$(python3 get_nonce.py --target http://fluent-test.local \\
      --cookie "$VICTIM_COOKIE")

  # Debug all pattern matches
  python3 get_nonce.py --target http://fluent-test.local \\
      --cookie "..." --verbose
        """
    )
    p.add_argument("--target",  required=True, help="WordPress base URL")
    p.add_argument("--cookie",  required=True, help="Admin session cookie header value")
    p.add_argument("--verbose", action="store_true", help="Show pattern match details on stderr")
    return p.parse_args()


def main():
    args = parse_args()
    nonce = run(args.target, args.cookie, args.verbose)
    if nonce:
        print(nonce)
        sys.exit(0)
    else:
        print("[fatal] Could not extract nonce from any admin page", file=sys.stderr)
        print("[hint]  Try --verbose to see which patterns were attempted", file=sys.stderr)
        print("[hint]  Verify the cookie belongs to an administrator account", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
