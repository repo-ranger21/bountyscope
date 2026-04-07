from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from supabase import Client
from backend.database import get_db

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetUpdate(BaseModel):
    status:   Optional[str] = None
    priority: Optional[str] = None
    notes:    Optional[str] = None


class FindingUpdate(BaseModel):
    status:         Optional[str] = None
    description:    Optional[str] = None
    poc_html:       Optional[str] = None
    remediation:    Optional[str] = None
    bounty_estimate: Optional[float] = None
    bounty_paid:    Optional[float] = None


# ── Targets ────────────────────────────────────────────────────

@router.get("/")
async def list_targets(
    status: Optional[str] = None,
    db: Client = Depends(get_db)
):
    q = db.table("targets").select("*").order("updated_at", desc=True)
    if status:
        q = q.eq("status", status)
    return q.execute().data


@router.get("/{slug}")
async def get_target(slug: str, db: Client = Depends(get_db)):
    resp = db.table("targets").select("*, findings(*), scans(*)").eq("slug", slug).limit(1).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail=f"Target '{slug}' not found.")
    return resp.data[0]


@router.patch("/{slug}")
async def update_target(slug: str, update: TargetUpdate, db: Client = Depends(get_db)):
    payload = {k: v for k, v in update.model_dump().items() if v is not None}
    if not payload:
        raise HTTPException(status_code=400, detail="No fields to update.")
    resp = db.table("targets").update(payload).eq("slug", slug).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail=f"Target '{slug}' not found.")
    return resp.data[0]


@router.delete("/{slug}")
async def delete_target(slug: str, db: Client = Depends(get_db)):
    db.table("targets").delete().eq("slug", slug).execute()
    return {"deleted": slug}


# ── Findings ───────────────────────────────────────────────────

@router.get("/{slug}/findings")
async def list_findings(slug: str, db: Client = Depends(get_db)):
    resp = (
        db.table("findings")
        .select("*")
        .eq("slug", slug)
        .order("created_at", desc=True)
        .execute()
    )
    return resp.data


@router.patch("/findings/{finding_id}")
async def update_finding(finding_id: str, update: FindingUpdate, db: Client = Depends(get_db)):
    payload = {k: v for k, v in update.model_dump().items() if v is not None}
    if not payload:
        raise HTTPException(status_code=400, detail="No fields to update.")
    resp = db.table("findings").update(payload).eq("id", finding_id).execute()
    if not resp.data:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return resp.data[0]


# ── Stats ──────────────────────────────────────────────────────

@router.get("/stats/summary")
async def get_stats(db: Client = Depends(get_db)):
    targets  = db.table("targets").select("status, in_scope, priority").execute().data
    findings = db.table("findings").select("status, severity, bounty_paid, bounty_estimate").execute().data

    total_paid     = sum(f.get("bounty_paid") or 0 for f in findings)
    total_estimate = sum(f.get("bounty_estimate") or 0 for f in findings)

    return {
        "targets": {
            "total":     len(targets),
            "in_scope":  sum(1 for t in targets if t.get("in_scope")),
            "by_status": _count_by(targets, "status"),
        },
        "findings": {
            "total":      len(findings),
            "by_status":  _count_by(findings, "status"),
            "by_severity": _count_by(findings, "severity"),
        },
        "bounties": {
            "total_paid":     total_paid,
            "total_estimate": total_estimate,
            "submitted":      sum(1 for f in findings if f.get("status") == "submitted"),
            "accepted":       sum(1 for f in findings if f.get("status") == "accepted"),
        },
    }


def _count_by(items: list, key: str) -> dict:
    counts: dict = {}
    for item in items:
        val = item.get(key, "unknown") or "unknown"
        counts[val] = counts.get(val, 0) + 1
    return counts
