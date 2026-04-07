from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from supabase import Client
from backend.database import get_db
from backend.services.csrf_scanner import scan_plugin
import time

router = APIRouter(prefix="/scanner", tags=["scanner"])


class ScanRequest(BaseModel):
    slug: str


@router.post("/scan")
async def run_scan(req: ScanRequest, db: Client = Depends(get_db)):
    """
    Download and scan a plugin for CSRF/nonce vulnerabilities.
    """
    slug  = req.slug.strip().lower()
    start = time.time()

    results = await scan_plugin(slug)

    if "error" in results:
        raise HTTPException(status_code=422, detail=results["message"])

    duration_ms = int((time.time() - start) * 1000)
    results["duration_ms"] = duration_ms

    # Persist scan to DB
    _save_scan(db, slug, results, duration_ms)

    # If likely vulnerable, auto-create a draft finding
    if results.get("verdict") == "likely_vulnerable" and results.get("confidence") in ("high", "medium"):
        _create_draft_finding(db, slug, results)

    return results


@router.get("/history/{slug}")
async def scan_history(slug: str, db: Client = Depends(get_db)):
    """Return past scan results for a plugin slug."""
    resp = (
        db.table("scans")
        .select("*")
        .eq("slug", slug)
        .order("scanned_at", desc=True)
        .limit(10)
        .execute()
    )
    return resp.data


def _save_scan(db, slug: str, results: dict, duration_ms: int):
    try:
        # Get target_id if exists
        target_resp = db.table("targets").select("id").eq("slug", slug).limit(1).execute()
        target_id   = target_resp.data[0]["id"] if target_resp.data else None

        db.table("scans").insert({
            "target_id":  target_id,
            "slug":       slug,
            "scan_type":  "csrf",
            "results":    results,
            "file_count": results.get("file_count", 0),
            "hit_count":  results.get("hit_count", 0),
            "duration_ms": duration_ms,
        }).execute()
    except Exception:
        pass


def _create_draft_finding(db, slug: str, results: dict):
    try:
        target_resp = db.table("targets").select("id").eq("slug", slug).limit(1).execute()
        target_id   = target_resp.data[0]["id"] if target_resp.data else None

        top_hits = results.get("top_hits", [])
        affected = list({h["file"] for h in top_hits})

        db.table("findings").insert({
            "target_id":      target_id,
            "slug":           slug,
            "vuln_type":      "csrf",
            "cwe":            "CWE-352",
            "severity":       "high",
            "cvss_score":     8.8,
            "affected_files": affected,
            "code_evidence":  top_hits[:10],
            "description":    (
                f"Plugin '{slug}' appears to process POST requests without nonce verification. "
                f"Found {results['hit_count']} potential vulnerable code paths across "
                f"{results['file_count']} PHP files with no nonce protection detected."
            ),
            "status":         "draft",
        }).execute()
    except Exception:
        pass
