import re
import os
import zipfile
import tempfile
import httpx
from pathlib import Path
from typing import Optional
from backend.config import CSRF_PATTERNS, NONCE_PATTERNS


async def download_plugin(slug: str, dest_dir: str) -> Optional[str]:
    """Download a plugin zip from WordPress.org SVN."""
    url = f"https://downloads.wordpress.org/plugin/{slug}.zip"
    zip_path = os.path.join(dest_dir, f"{slug}.zip")

    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        resp = await client.get(url)
        if resp.status_code != 200 or len(resp.content) < 1000:
            return None
        with open(zip_path, "wb") as f:
            f.write(resp.content)

    return zip_path


def extract_plugin(zip_path: str, dest_dir: str) -> str:
    """Extract plugin zip, return path to extracted directory."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest_dir)
    # Return first subdirectory (plugin folder)
    for item in os.listdir(dest_dir):
        full = os.path.join(dest_dir, item)
        if os.path.isdir(full):
            return full
    return dest_dir


def scan_directory(plugin_dir: str) -> dict:
    """
    Run full CSRF/nonce static analysis against a plugin directory.
    Returns structured findings dict.
    """
    php_files = list(Path(plugin_dir).rglob("*.php"))

    # Collect all hits
    vuln_hits   = []  # patterns that indicate vulnerable code
    nonce_hits  = []  # patterns that indicate nonce usage
    file_count  = len(php_files)

    for php_file in php_files:
        rel_path = str(php_file.relative_to(plugin_dir))
        try:
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            lines   = content.splitlines()
        except Exception:
            continue

        # Scan for vulnerable patterns
        for pattern_name, pattern in CSRF_PATTERNS.items():
            for lineno, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    vuln_hits.append({
                        "file":    rel_path,
                        "line":    lineno,
                        "pattern": pattern_name,
                        "snippet": line.strip()[:200],
                    })

        # Scan for nonce patterns
        for pattern_name, pattern in NONCE_PATTERNS.items():
            for lineno, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    nonce_hits.append({
                        "file":    rel_path,
                        "line":    lineno,
                        "pattern": pattern_name,
                        "snippet": line.strip()[:200],
                    })

    # Determine vulnerability verdict
    has_ajax_handlers = any(h["pattern"] == "ajax_handlers" for h in vuln_hits)
    has_admin_post    = any(h["pattern"] == "admin_post"    for h in vuln_hits)
    has_state_changes = any(h["pattern"] in {
        "update_option", "add_option", "delete_option",
        "wp_insert", "wp_update", "wp_delete"
    } for h in vuln_hits)
    has_post_data     = any(h["pattern"] in {"post_data", "get_data", "request_data"}
                            for h in vuln_hits)
    has_nonces        = len(nonce_hits) > 0

    # Confidence scoring
    confidence = _score_confidence(
        has_ajax_handlers, has_admin_post,
        has_state_changes, has_post_data, has_nonces
    )

    verdict = "likely_vulnerable" if (
        (has_ajax_handlers or has_admin_post or has_state_changes)
        and not has_nonces
    ) else ("nonce_protected" if has_nonces else "no_handlers_found")

    return {
        "file_count":       file_count,
        "hit_count":        len(vuln_hits),
        "nonce_hit_count":  len(nonce_hits),
        "verdict":          verdict,
        "confidence":       confidence,
        "has_ajax_handlers":  has_ajax_handlers,
        "has_admin_post":     has_admin_post,
        "has_state_changes":  has_state_changes,
        "has_post_data":      has_post_data,
        "has_nonces":         has_nonces,
        "vuln_hits":          vuln_hits[:100],   # cap for DB storage
        "nonce_hits":         nonce_hits[:50],
        "top_hits":           _top_hits(vuln_hits),
    }


def _score_confidence(ajax, admin_post, state_changes, post_data, has_nonces) -> str:
    if has_nonces:
        return "low"
    score = sum([ajax, admin_post, state_changes, post_data])
    if score >= 3:
        return "high"
    if score == 2:
        return "medium"
    if score == 1:
        return "low"
    return "none"


def _top_hits(hits: list[dict]) -> list[dict]:
    """Return the highest-signal hits for quick display."""
    priority_order = [
        "ajax_handlers", "admin_post", "update_option",
        "add_option", "delete_option", "post_data",
        "wp_insert", "wp_update", "wp_delete",
    ]
    seen_files = set()
    top = []
    for pattern in priority_order:
        for h in hits:
            if h["pattern"] == pattern and h["file"] not in seen_files:
                top.append(h)
                seen_files.add(h["file"])
                if len(top) >= 10:
                    return top
    return top


async def scan_plugin(slug: str, use_semgrep: bool = True) -> dict:
    """
    Full pipeline: download → extract → scan → return results.
    Uses semgrep as primary engine with grep as fallback.
    """
    from backend.services.semgrep_scanner import run_semgrep, semgrep_available

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = await download_plugin(slug, tmpdir)
        if not zip_path:
            return {
                "error":   "download_failed",
                "message": f"Could not download plugin '{slug}'. It may be closed or not exist.",
                "slug":    slug,
            }

        plugin_dir = extract_plugin(zip_path, tmpdir)

        # Primary: semgrep AST analysis
        semgrep_results = {}
        if use_semgrep and semgrep_available():
            semgrep_results = run_semgrep(plugin_dir)

        # Secondary: grep-based analysis (always runs)
        grep_results = scan_directory(plugin_dir)

        # Merge — semgrep verdict takes precedence if available
        if semgrep_results and "error" not in semgrep_results:
            results = _merge_results(grep_results, semgrep_results)
        else:
            results = grep_results
            results["semgrep_error"] = semgrep_results.get("message", "semgrep unavailable")

        results["slug"]    = slug
        results["engines"] = ["semgrep", "grep"] if semgrep_results and "error" not in semgrep_results else ["grep"]
        return results


def _merge_results(grep: dict, semgrep: dict) -> dict:
    """
    Merge grep and semgrep results into unified output.
    Semgrep findings are higher signal — elevate verdict accordingly.
    """
    # Take the more severe verdict
    verdict_priority = {
        "likely_vulnerable":   3,
        "needs_manual_review": 2,
        "nonce_protected":     1,
        "no_handlers_found":   0,
        "clean":               0,
    }

    grep_priority    = verdict_priority.get(grep.get("verdict", ""), 0)
    semgrep_priority = verdict_priority.get(semgrep.get("verdict", ""), 0)

    final_verdict = (
        semgrep.get("verdict") if semgrep_priority >= grep_priority
        else grep.get("verdict")
    )

    # Confidence — take highest
    conf_priority = {"high": 3, "medium": 2, "low": 1, "none": 0}
    grep_conf    = conf_priority.get(grep.get("confidence", "none"), 0)
    semgrep_conf = conf_priority.get(semgrep.get("confidence", "none"), 0)
    final_conf   = semgrep.get("confidence") if semgrep_conf >= grep_conf else grep.get("confidence")

    return {
        # Grep signals
        "file_count":         grep.get("file_count", 0),
        "hit_count":          grep.get("hit_count", 0),
        "nonce_hit_count":    grep.get("nonce_hit_count", 0),
        "has_ajax_handlers":  grep.get("has_ajax_handlers", False),
        "has_admin_post":     grep.get("has_admin_post", False),
        "has_state_changes":  grep.get("has_state_changes", False),
        "has_post_data":      grep.get("has_post_data", False),
        "has_nonces":         grep.get("has_nonces", False),
        "top_hits":           grep.get("top_hits", []),

        # Semgrep findings
        "semgrep_findings":      semgrep.get("findings", []),
        "semgrep_total":         semgrep.get("total_findings", 0),
        "semgrep_high_threat":   semgrep.get("high_threat_count", 0),
        "semgrep_vuln_types":    semgrep.get("vuln_types_found", []),
        "semgrep_top":           semgrep.get("top_findings", []),

        # Merged verdict
        "verdict":      final_verdict,
        "confidence":   final_conf,
    }
