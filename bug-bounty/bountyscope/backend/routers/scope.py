from fastapi import APIRouter, HTTPException, Depends
from supabase import Client
from backend.database import get_db
from backend.config import get_settings, SCOPE_THRESHOLDS, HIGH_THREAT_TYPES, COMMON_DANGEROUS_TYPES
from backend.services.wordpress_api import fetch_plugin_info
from backend.services.wordfence_api import fetch_existing_cves, estimate_bounty
from backend.services.wpscan_api import fetch_wpscan_vulns, compare_sources
from backend.services.patchstack_api import fetch_patchstack_vulns, merge_patchstack_into_cross_ref

router = APIRouter(prefix="/scope", tags=["scope"])


@router.get("/{slug}")
async def check_scope(slug: str, db: Client = Depends(get_db)):
    """
    Full scope eligibility check for a plugin slug.
    Hits WordPress.org API + Wordfence Intel, evaluates scope by tier.
    """
    slug = slug.strip().lower()

    # 1. Fetch plugin info from WordPress.org
    plugin_info = await fetch_plugin_info(slug)
    closed = plugin_info is None

    if closed:
        # Plugin not found — could be closed or never existed
        plugin_info = {
            "slug":          slug,
            "name":          slug,
            "author":        "unknown",
            "version":       "unknown",
            "install_count": 0,
            "repo_status":   "closed",
            "last_updated":  "",
            "download_link": "",
        }

    install_count = plugin_info.get("install_count", 0)
    settings      = get_settings()
    tier          = settings.researcher_tier

    # 2. Fetch existing CVEs from Wordfence + WPScan + Patchstack
    existing_cves      = await fetch_existing_cves(slug)
    wpscan_result      = await fetch_wpscan_vulns(slug)
    patchstack_result  = await fetch_patchstack_vulns(slug)
    cross_ref          = compare_sources(existing_cves, wpscan_result)
    cross_ref          = merge_patchstack_into_cross_ref(cross_ref, patchstack_result, existing_cves)
    has_known_cve      = (
        len(existing_cves) > 0
        or wpscan_result.get("vuln_count", 0) > 0
        or patchstack_result.get("vuln_count", 0) > 0
    )

    # 3. Evaluate scope for each vuln class
    scope_matrix = _build_scope_matrix(install_count, tier, closed)

    # 4. Overall verdict
    any_in_scope   = any(v["in_scope"] for v in scope_matrix.values())
    risk_level     = _risk_level(install_count)

    # 5. Bounty estimates
    bounty_estimates = {}
    for vuln_class in ["csrf", "stored_xss", "rce", "auth_bypass"]:
        bounty_estimates[vuln_class] = estimate_bounty(install_count, 9.0, vuln_class)

    result = {
        "slug":             slug,
        "plugin":           plugin_info,
        "closed":           closed,
        "install_count":    install_count,
        "risk_level":       risk_level,
        "researcher_tier":  tier,
        "any_in_scope":     any_in_scope,
        "scope_matrix":     scope_matrix,
        "has_known_cve":    has_known_cve,
        "existing_cves":    existing_cves,
        "wpscan":           wpscan_result,
        "patchstack":       patchstack_result,
        "cross_reference":  cross_ref,
        "duplicate_risk":   cross_ref.get("duplicate_risk", "low"),
        "bounty_estimates": bounty_estimates,
        "recommendation":   _recommendation(any_in_scope, has_known_cve, closed, install_count),
    }

    # 6. Upsert to DB
    _upsert_target(db, slug, plugin_info, result, existing_cves)

    return result


def _build_scope_matrix(install_count: int, tier: str, closed: bool) -> dict:
    thresholds = {
        "high_threat":      SCOPE_THRESHOLDS["high_threat"],
        "common_dangerous": SCOPE_THRESHOLDS["common_dangerous"],
        "other":            SCOPE_THRESHOLDS["other"][tier],
    }

    matrix = {}
    for vuln_class, threshold in thresholds.items():
        in_scope = install_count >= threshold and not closed
        matrix[vuln_class] = {
            "in_scope":       in_scope,
            "threshold":      threshold,
            "install_count":  install_count,
            "gap":            max(0, threshold - install_count),
            "closed_blocks":  closed,
        }
    return matrix


def _risk_level(install_count: int) -> str:
    if install_count >= 1_000_000: return "critical"
    if install_count >= 100_000:   return "high"
    if install_count >= 10_000:    return "medium"
    if install_count >= 1_000:     return "low"
    return "minimal"


def _recommendation(in_scope: bool, has_cve: bool, closed: bool, installs: int) -> str:
    if closed:
        return "SKIP — Plugin is closed. No patch path, likely low install base."
    if has_cve:
        return "CAUTION — Known CVEs exist. Verify your finding is not a duplicate before investing time."
    if not in_scope:
        return f"OUT OF SCOPE — Install count ({installs:,}) below your tier threshold. Skip unless you upgrade tier."
    if installs >= 100_000:
        return "HIGH PRIORITY — In scope with strong install count. Excellent target."
    if installs >= 50_000:
        return "GOOD TARGET — In scope. Worth investigating."
    return "IN SCOPE — Proceed with scan."


def _upsert_target(db, slug, plugin_info, result, existing_cves):
    try:
        db.table("targets").upsert({
            "slug":             slug,
            "name":             plugin_info.get("name"),
            "author":           plugin_info.get("author"),
            "version":          plugin_info.get("version"),
            "install_count":    plugin_info.get("install_count", 0),
            "last_updated":     plugin_info.get("last_updated", ""),
            "repo_status":      "closed" if result["closed"] else "active",
            "in_scope":         result["any_in_scope"],
            "scope_tier":       result["researcher_tier"],
            "scope_notes":      result["recommendation"],
            "wordfence_cves":   existing_cves,
            "status":           "queued",
        }, on_conflict="slug").execute()
    except Exception:
        pass  # Non-fatal — DB write failure shouldn't break the response
