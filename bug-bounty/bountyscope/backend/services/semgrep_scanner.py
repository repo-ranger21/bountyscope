"""
Semgrep-powered WordPress vulnerability scanner.
Replaces regex grep with AST-aware static analysis.
Finds CSRF, Missing Authorization, SQLi, and more
with dramatically lower false positive rate.
"""

import json
import subprocess
import shutil
import os
from pathlib import Path
from typing import Optional


RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                          "semgrep", "rules")

# Severity → CVSS mapping from rule metadata
SEVERITY_MAP = {
    "ERROR":   "high",
    "WARNING": "medium",
    "INFO":    "low",
}

# Wordfence vuln type classification
HIGH_THREAT_TYPES = {
    "arbitrary_options_update",
    "arbitrary_file_deletion",
    "arbitrary_file_upload",
    "privilege_escalation",
    "account_takeover",
    "remote_code_execution",
    "authentication_bypass",
}


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def run_semgrep(target_dir: str, rules_path: Optional[str] = None) -> dict:
    """
    Run semgrep against a plugin directory using our custom WordPress rules.
    Returns structured findings dict.
    """
    if not semgrep_available():
        return {"error": "semgrep_not_installed",
                "message": "Install semgrep: pip install semgrep"}

    rules = rules_path or RULES_DIR

    cmd = [
        "semgrep",
        "--config", rules,
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--lang", "php",
        target_dir,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode not in (0, 1):
            return {
                "error":   "semgrep_error",
                "message": result.stderr[:500] if result.stderr else "Unknown error",
                "findings": [],
            }

        output = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
        raw_findings = output.get("results", [])

        return _process_findings(raw_findings, target_dir)

    except subprocess.TimeoutExpired:
        return {"error": "timeout", "message": "Semgrep timed out after 120s", "findings": []}
    except json.JSONDecodeError:
        return {"error": "parse_error", "message": "Could not parse semgrep output", "findings": []}
    except Exception as e:
        return {"error": "unexpected", "message": str(e), "findings": []}


def _process_findings(raw: list, base_dir: str) -> dict:
    """Transform raw semgrep output into structured BountyScope findings."""
    findings = []
    high_threat_count = 0
    vuln_types_found  = set()

    for hit in raw:
        check_id  = hit.get("check_id", "")
        meta      = hit.get("extra", {}).get("metadata", {})
        severity  = hit.get("extra", {}).get("severity", "WARNING")
        message   = hit.get("extra", {}).get("message", "")
        path      = hit.get("path", "")
        start     = hit.get("start", {})
        end       = hit.get("end", {})
        lines     = hit.get("extra", {}).get("lines", "")

        # Make path relative
        rel_path = os.path.relpath(path, base_dir) if base_dir in path else path

        vuln_class    = meta.get("vuln_class", "unknown")
        wordfence_type = meta.get("wordfence_type", "other")
        cvss          = float(meta.get("cvss", "0").replace('"', ''))
        confidence    = meta.get("confidence", "MEDIUM")
        cwe           = meta.get("cwe", "")

        is_high_threat = wordfence_type == "high_threat" or vuln_class in HIGH_THREAT_TYPES
        if is_high_threat:
            high_threat_count += 1

        vuln_types_found.add(vuln_class)

        findings.append({
            "rule_id":       check_id,
            "vuln_class":    vuln_class,
            "wordfence_type": wordfence_type,
            "is_high_threat": is_high_threat,
            "severity":      SEVERITY_MAP.get(severity, "medium"),
            "cvss":          cvss,
            "cwe":           cwe,
            "confidence":    confidence,
            "message":       message.strip(),
            "file":          rel_path,
            "line_start":    start.get("line", 0),
            "line_end":      end.get("line", 0),
            "code_snippet":  lines.strip()[:300],
        })

    # Sort by severity then cvss
    findings.sort(key=lambda x: (x["cvss"], x["confidence"]), reverse=True)

    # Overall verdict
    error_count   = sum(1 for f in findings if f["severity"] == "high")
    warning_count = sum(1 for f in findings if f["severity"] == "medium")

    if error_count > 0:
        verdict    = "likely_vulnerable"
        confidence = "high" if error_count >= 2 else "medium"
    elif warning_count > 0:
        verdict    = "needs_manual_review"
        confidence = "low"
    else:
        verdict    = "clean"
        confidence = "none"

    return {
        "engine":            "semgrep",
        "verdict":           verdict,
        "confidence":        confidence,
        "total_findings":    len(findings),
        "high_threat_count": high_threat_count,
        "error_count":       error_count,
        "warning_count":     warning_count,
        "vuln_types_found":  list(vuln_types_found),
        "findings":          findings,
        "top_findings":      findings[:10],
    }


def summarize_for_report(semgrep_results: dict) -> str:
    """Generate a human-readable summary of semgrep findings."""
    if "error" in semgrep_results:
        return f"Semgrep error: {semgrep_results['message']}"

    findings = semgrep_results.get("findings", [])
    if not findings:
        return "No vulnerabilities detected by semgrep."

    lines = [f"Semgrep detected {len(findings)} potential issue(s):\n"]
    for f in findings[:5]:
        lines.append(
            f"  [{f['severity'].upper()}] {f['vuln_class']} — "
            f"{f['file']}:{f['line_start']}\n"
            f"  CVSS: {f['cvss']} | Confidence: {f['confidence']}\n"
            f"  {f['message'][:120]}\n"
        )

    return "\n".join(lines)
