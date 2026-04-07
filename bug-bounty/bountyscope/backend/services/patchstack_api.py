"""
Patchstack vulnerability database integration.
Second duplicate-check source alongside Wordfence and WPScan.

Patchstack indexes vulns from their own bug bounty program — benzdeus and
other researchers submit there first. If Wordfence doesn't have it,
Patchstack often does. Today's lesson: WCFM CVE-2025-64631 and
CVE-2026-1722 were in Patchstack months before Wordfence caught them.

API Key: Free tier at https://patchstack.com/register
Add to .env: PATCHSTACK_API_TOKEN=your_key_here

Free tier quota: 100 requests/day
"""

import httpx
import os
from typing import Optional

PATCHSTACK_API = "https://api.patchstack.com/cyberinsurance/v2"


async def fetch_patchstack_vulns(slug: str, api_token: Optional[str] = None) -> dict:
    """
    Query Patchstack API for known vulnerabilities against a plugin slug.

    Returns structured vuln list with duplicate_risk flag.
    Gracefully degrades to no_api_token if key not set.
    """
    try:
        from backend.config import get_settings
        token = api_token or get_settings().patchstack_api_token or os.environ.get("PATCHSTACK_API_TOKEN", "")
    except Exception:
        token = api_token or os.environ.get("PATCHSTACK_API_TOKEN", "")

    if not token:
        return {
            "available":      False,
            "reason":         "no_api_token",
            "message":        "Set PATCHSTACK_API_TOKEN in .env — free at patchstack.com/register",
            "vulns":          [],
            "vuln_count":     0,
            "duplicate_risk": "unknown",
        }

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/json",
        "User-Agent":    "BountyScope/2.0 (@lucius-log)",
    }

    params = {
        "component_slug": slug,
        "limit":          25,
    }

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(
                f"{PATCHSTACK_API}/vulnerabilities",
                headers=headers,
                params=params,
            )

            if resp.status_code == 401:
                return {
                    "available":      False,
                    "reason":         "invalid_token",
                    "message":        "Patchstack API token invalid or expired.",
                    "vulns":          [],
                    "vuln_count":     0,
                    "duplicate_risk": "unknown",
                }

            if resp.status_code == 403:
                return {
                    "available":      False,
                    "reason":         "forbidden",
                    "message":        "Patchstack API access denied. Check token permissions.",
                    "vulns":          [],
                    "vuln_count":     0,
                    "duplicate_risk": "unknown",
                }

            if resp.status_code == 429:
                return {
                    "available":      False,
                    "reason":         "rate_limited",
                    "message":        "Patchstack API rate limit hit (100/day free tier).",
                    "vulns":          [],
                    "vuln_count":     0,
                    "duplicate_risk": "unknown",
                }

            if resp.status_code == 404:
                return {
                    "available":      True,
                    "reason":         "not_found",
                    "message":        f"Plugin '{slug}' not in Patchstack database.",
                    "vulns":          [],
                    "vuln_count":     0,
                    "duplicate_risk": "low",
                }

            if resp.status_code != 200:
                return {
                    "available":      False,
                    "reason":         f"http_{resp.status_code}",
                    "message":        f"Patchstack API returned {resp.status_code}.",
                    "vulns":          [],
                    "vuln_count":     0,
                    "duplicate_risk": "unknown",
                }

            data  = resp.json()
            items = data.get("data", data) if isinstance(data, dict) else data
            if not isinstance(items, list):
                items = []

            processed = []
            for v in items:
                processed.append({
                    "title":          v.get("title", v.get("vulnerability_title", "")),
                    "cve":            v.get("cve_id", v.get("cve", "No CVE")),
                    "cvss":           v.get("cvss_score", v.get("cvss", 0)),
                    "severity":       v.get("severity", _severity_from_cvss(
                                          v.get("cvss_score", v.get("cvss", 0)))),
                    "vuln_type":      v.get("vulnerability_type",
                                           v.get("type", "Unknown")),
                    "affected_in":    v.get("affected_version",
                                           v.get("affected_in", "")),
                    "patched_in":     v.get("patched_in_version",
                                           v.get("patched_in", "No fix")),
                    "researcher":     _extract_researcher(v),
                    "published":      v.get("published_date",
                                           v.get("date", "")),
                    "patchstack_id":  v.get("psid", v.get("id", "")),
                    "url":            v.get("url", ""),
                })

            return {
                "available":      True,
                "slug":           slug,
                "vuln_count":     len(processed),
                "vulns":          processed,
                "duplicate_risk": "high" if processed else "low",
                "source":         "patchstack",
            }

        except httpx.RequestError as e:
            return {
                "available":      False,
                "reason":         "network_error",
                "message":        str(e),
                "vulns":          [],
                "vuln_count":     0,
                "duplicate_risk": "unknown",
            }


def _extract_researcher(vuln: dict) -> str:
    """Pull researcher name from various Patchstack response shapes."""
    # Try direct fields
    for key in ("researcher", "credits", "credit", "reported_by", "finder"):
        val = vuln.get(key)
        if val:
            if isinstance(val, str):
                return val
            if isinstance(val, dict):
                return val.get("name", val.get("username", str(val)))
            if isinstance(val, list) and val:
                first = val[0]
                return first.get("name", first.get("username", str(first))) \
                       if isinstance(first, dict) else str(first)
    return "Unknown"


def _severity_from_cvss(score) -> str:
    """Map CVSS score to severity label."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if s >= 9.0: return "critical"
    if s >= 7.0: return "high"
    if s >= 4.0: return "medium"
    if s >  0.0: return "low"
    return "info"


def merge_patchstack_into_cross_ref(
    cross_ref: dict,
    patchstack_result: dict,
    wordfence_cves: list,
) -> dict:
    """
    Extend the existing cross_ref dict (from compare_sources) with
    Patchstack findings. Adds patchstack_count, combined duplicate_risk,
    and flags CVEs found only in Patchstack — the gap benzdeus exploited.
    """
    ps_vulns    = patchstack_result.get("vulns", [])
    ps_cve_ids  = {v.get("cve", "") for v in ps_vulns if v.get("cve", "No CVE") != "No CVE"}
    wf_cve_ids  = {c.get("cve", "") for c in wordfence_cves}
    ws_cve_ids  = set(cross_ref.get("only_in_wpscan", [])) | set(cross_ref.get("confirmed_in_both", []))

    all_known   = wf_cve_ids | ws_cve_ids | ps_cve_ids
    only_in_ps  = ps_cve_ids - wf_cve_ids - ws_cve_ids

    # Escalate duplicate risk if Patchstack has findings Wordfence missed
    base_risk = cross_ref.get("duplicate_risk", "low")
    if ps_cve_ids:
        combined_risk = "high"
    elif base_risk == "high":
        combined_risk = "high"
    else:
        combined_risk = base_risk

    cross_ref.update({
        "patchstack_count":    len(ps_cve_ids),
        "patchstack_vulns":    ps_vulns,
        "only_in_patchstack":  list(only_in_ps),
        "all_known_cves":      list(all_known),
        "duplicate_risk":      combined_risk,
        "patchstack_available": patchstack_result.get("available", False),
        "recommendation":      _three_source_rec(wf_cve_ids, ws_cve_ids, ps_cve_ids,
                                                  patchstack_result.get("available", False)),
    })
    return cross_ref


def _three_source_rec(wf: set, ws: set, ps: set, ps_available: bool) -> str:
    if not ps_available:
        return (
            "Patchstack check skipped (no API token). Add PATCHSTACK_API_TOKEN to .env "
            "— this is how WCFM CVE-2025-64631 was missed today."
        )
    all_known = wf | ws | ps
    if not all_known:
        return "No CVEs in Wordfence, WPScan, or Patchstack. Lowest duplicate risk — green light to scan."
    only_ps = ps - wf - ws
    if only_ps:
        return (
            f"WARNING: {len(only_ps)} CVE(s) exist in Patchstack but NOT Wordfence/WPScan: "
            f"{', '.join(only_ps)}. High duplicate risk — verify your finding differs from these."
        )
    if all_known:
        return (
            f"{len(all_known)} known CVE(s) across all sources. "
            "High duplicate risk — review each before investing research time."
        )
    return "Clean across all three sources. Proceed."
