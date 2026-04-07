import httpx
from typing import Optional

WF_API = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/software"


async def fetch_existing_cves(slug: str) -> list[dict]:
    """
    Query Wordfence Intelligence API for known CVEs against a plugin slug.
    Returns list of vulnerability dicts or empty list.
    """
    url = f"{WF_API}/plugin/{slug}"

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return []

            data = resp.json()
            if not data:
                return []

            results = []
            for cve_id, vuln in data.items():
                results.append({
                    "cve":         cve_id,
                    "title":       vuln.get("title", ""),
                    "cvss":        vuln.get("cvss", {}).get("score", 0),
                    "cvss_vector": vuln.get("cvss", {}).get("vector", ""),
                    "vuln_type":   _extract_vuln_type(vuln),
                    "published":   vuln.get("published", ""),
                    "updated":     vuln.get("updated", ""),
                    "status":      vuln.get("status", ""),
                    "researchers": _extract_researchers(vuln),
                    "patched_in":  vuln.get("patched_in_version", ""),
                    "url":         f"https://www.wordfence.com/threat-intel/vulnerabilities/id/{vuln.get('id', '')}",
                })

            return sorted(results, key=lambda x: x.get("published", ""), reverse=True)

        except (httpx.RequestError, ValueError):
            return []


def _extract_vuln_type(vuln: dict) -> str:
    types = vuln.get("vulnerability_types", [])
    if types and isinstance(types, list):
        return types[0].get("slug", "unknown")
    return "unknown"


def _extract_researchers(vuln: dict) -> list[str]:
    researchers = vuln.get("researchers", [])
    return [r.get("display_name", "") for r in researchers if r.get("display_name")]


def estimate_bounty(install_count: int, cvss: float, vuln_type: str) -> dict:
    """
    Rough bounty estimate based on Wordfence payout structure.
    Not a guarantee — use as directional signal only.
    """
    from backend.config import HIGH_THREAT_TYPES, COMMON_DANGEROUS_TYPES

    if vuln_type in HIGH_THREAT_TYPES:
        if install_count >= 1_000_000:
            base = 3_000
        elif install_count >= 100_000:
            base = 1_000
        elif install_count >= 10_000:
            base = 500
        elif install_count >= 1_000:
            base = 200
        else:
            base = 100
    elif vuln_type in COMMON_DANGEROUS_TYPES:
        if install_count >= 1_000_000:
            base = 1_500
        elif install_count >= 100_000:
            base = 500
        elif install_count >= 10_000:
            base = 250
        else:
            base = 100
    else:
        # CSRF and other
        if install_count >= 1_000_000:
            base = 800
        elif install_count >= 100_000:
            base = 300
        elif install_count >= 50_000:
            base = 150
        else:
            base = 50

    # CVSS modifier
    if cvss >= 9.0:
        multiplier = 1.5
    elif cvss >= 7.0:
        multiplier = 1.2
    elif cvss >= 5.0:
        multiplier = 1.0
    else:
        multiplier = 0.6

    estimate = round(base * multiplier, 2)
    return {
        "estimate":   estimate,
        "base":       base,
        "multiplier": multiplier,
        "note":       "Directional estimate only. Actual payout set by Wordfence.",
    }
