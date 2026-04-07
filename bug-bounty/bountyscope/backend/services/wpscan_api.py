import httpx
import os
from typing import Optional

WPSCAN_API = "https://wpscan.com/api/v3"


async def fetch_wpscan_vulns(slug: str, api_token: Optional[str] = None) -> dict:
    try:
        from backend.config import get_settings
        token = api_token or get_settings().wpscan_api_token or os.environ.get("WPSCAN_API_TOKEN", "")
    except Exception:
        token = api_token or os.environ.get("WPSCAN_API_TOKEN", "")

    if not token:
        return {"available": False, "reason": "no_api_token",
                "message": "Set WPSCAN_API_TOKEN in .env", "vulns": [], "vuln_count": 0}

    headers = {
        "Authorization": f"Token token={token}",
        "User-Agent": "BountyScope/2.0 (@lucius-log)",
    }

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(f"{WPSCAN_API}/plugins/{slug}", headers=headers)

            if resp.status_code == 401:
                return {"available": False, "reason": "invalid_token", "vulns": [], "vuln_count": 0}
            if resp.status_code == 404:
                return {"available": True, "reason": "not_found", "vulns": [], "vuln_count": 0}
            if resp.status_code == 429:
                return {"available": False, "reason": "rate_limited", "vulns": [], "vuln_count": 0}
            if resp.status_code != 200:
                return {"available": False, "reason": f"http_{resp.status_code}", "vulns": [], "vuln_count": 0}

            data = resp.json()
            plugin = data.get(slug, {})
            vulns = plugin.get("vulnerabilities", [])

            processed = []
            for v in vulns:
                refs = v.get("references", {})
                cves = refs.get("cve", [])
                processed.append({
                    "title":    v.get("title", ""),
                    "cve":      f"CVE-{cves[0]}" if cves else "No CVE",
                    "vuln_type": v.get("vuln_type", "UNKNOWN"),
                    "fixed_in": v.get("fixed_in", "Not fixed"),
                    "cvss":     (v.get("cvss") or {}).get("score", 0),
                })

            return {
                "available":      True,
                "slug":           slug,
                "vuln_count":     len(processed),
                "vulns":          processed,
                "duplicate_risk": "high" if processed else "low",
            }

        except httpx.RequestError as e:
            return {"available": False, "reason": "network_error",
                    "message": str(e), "vulns": [], "vuln_count": 0}


def compare_sources(wordfence_cves: list, wpscan_result: dict) -> dict:
    wf_cve_ids = {c.get("cve", "") for c in wordfence_cves}
    ws_cve_ids = {v.get("cve", "") for v in wpscan_result.get("vulns", [])}

    only_in_wordfence = wf_cve_ids - ws_cve_ids
    only_in_wpscan    = ws_cve_ids - wf_cve_ids
    in_both           = wf_cve_ids & ws_cve_ids

    return {
        "wordfence_count":   len(wf_cve_ids),
        "wpscan_count":      len(ws_cve_ids),
        "confirmed_in_both": list(in_both),
        "only_in_wordfence": list(only_in_wordfence),
        "only_in_wpscan":    list(only_in_wpscan),
        "duplicate_risk":    "high" if in_both or (wf_cve_ids or ws_cve_ids) else "low",
    }
