#!/usr/bin/env python3
"""
BountyScope CLI — WordPress Bug Bounty Research Workstation
@lucius-log | repo-ranger21/bountyscope

Usage:
  bountyscope scope <slug>
  bountyscope scan <slug>
  bountyscope targets [list|show|update|stats]
"""

import asyncio
import sys
import os
import json
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from backend.services.wordpress_api import fetch_plugin_info
from backend.services.wordfence_api import fetch_existing_cves, estimate_bounty
from backend.services.patchstack_api import fetch_patchstack_vulns
from backend.services.wpscan_api import fetch_wpscan_vulns
from backend.services.csrf_scanner import scan_plugin
from backend.config import get_settings, SCOPE_THRESHOLDS

console  = Console()
settings = get_settings()


# ── Helpers ────────────────────────────────────────────────────

def scope_color(in_scope: bool) -> str:
    return "green" if in_scope else "red"

def verdict_color(verdict: str) -> str:
    return {
        "likely_vulnerable": "red",
        "nonce_protected":   "green",
        "no_handlers_found": "yellow",
    }.get(verdict, "white")

def confidence_color(confidence: str) -> str:
    return {"high": "red", "medium": "yellow", "low": "cyan", "none": "dim"}.get(confidence, "white")

def severity_color(s: str) -> str:
    return {"critical": "red", "high": "orange3", "medium": "yellow", "low": "cyan", "info": "dim"}.get(s, "white")


# ── CLI Group ──────────────────────────────────────────────────

@click.group()
def cli():
    """BountyScope — WordPress Bug Bounty Research Workstation"""
    pass


# ── Scope Checker ──────────────────────────────────────────────

@cli.command()
@click.argument("slug")
@click.option("--tier", default=None, help="Researcher tier: standard|resourceful|1337")
@click.option("--json-out", is_flag=True, help="Output raw JSON")
def scope(slug: str, tier: str, json_out: bool):
    """Check if a plugin slug is in scope for your researcher tier."""

    async def _run():
        slug_clean = slug.strip().lower()
        _tier = tier or settings.researcher_tier

        with Progress(SpinnerColumn(), TextColumn("[bold blue]Checking scope..."), transient=True) as p:
            p.add_task("", total=None)
            plugin_info       = await fetch_plugin_info(slug_clean)
            existing_cves     = await fetch_existing_cves(slug_clean)
            patchstack_result = await fetch_patchstack_vulns(slug_clean)
            wpscan_result     = await fetch_wpscan_vulns(slug_clean)

        closed        = plugin_info is None
        install_count = (plugin_info or {}).get("install_count", 0)
        ps_vulns      = patchstack_result.get("vulns", [])
        ps_available  = patchstack_result.get("available", False)
        ps_reason     = patchstack_result.get("reason", "")
        ws_vulns      = wpscan_result.get("vulns", [])

        if json_out:
            click.echo(json.dumps({
                "slug":          slug_clean,
                "plugin":        plugin_info,
                "closed":        closed,
                "install_count": install_count,
                "existing_cves": existing_cves,
                "patchstack":    patchstack_result,
            }, indent=2, default=str))
            return

        # ── Header panel ───────────────────────────────────────
        status_str = "[red]CLOSED[/red]" if closed else "[green]ACTIVE[/green]"
        name   = (plugin_info or {}).get("name", slug_clean)
        author = (plugin_info or {}).get("author", "unknown")
        version = (plugin_info or {}).get("version", "unknown")

        console.print(Panel(
            f"[bold]{name}[/bold]  {status_str}\n"
            f"[dim]slug:[/dim] {slug_clean}   [dim]author:[/dim] {author}   "
            f"[dim]version:[/dim] {version}\n"
            f"[dim]installs:[/dim] [bold]{install_count:,}[/bold]   "
            f"[dim]tier:[/dim] {_tier}",
            title="[bold blue]BountyScope — Scope Check[/bold blue]",
            border_style="blue",
        ))

        # ── Scope matrix ───────────────────────────────────────
        tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold dim")
        tbl.add_column("Vuln Class",    style="bold")
        tbl.add_column("Threshold",     justify="right")
        tbl.add_column("Your Installs", justify="right")
        tbl.add_column("In Scope",      justify="center")
        tbl.add_column("Gap")

        thresholds = {
            "High Threat (RCE/AuthBypass/PrivEsc)": SCOPE_THRESHOLDS["high_threat"],
            "Common Dangerous (XSS/SQLi)":          SCOPE_THRESHOLDS["common_dangerous"],
            "Other (CSRF, etc)":                    SCOPE_THRESHOLDS["other"][_tier],
        }

        any_in_scope = False
        for vuln_class, threshold in thresholds.items():
            in_scope = install_count >= threshold and not closed
            if in_scope:
                any_in_scope = True
            gap     = max(0, threshold - install_count)
            gap_str = f"[red]-{gap:,}[/red]" if gap > 0 else "[green]✓[/green]"
            tbl.add_row(
                vuln_class,
                f"{threshold:,}",
                f"{install_count:,}",
                f"[{scope_color(in_scope)}]{'YES' if in_scope else 'NO'}[/{scope_color(in_scope)}]",
                gap_str,
            )

        console.print(tbl)

        # ── Duplicate Risk Block ───────────────────────────────
        total_known = len(existing_cves) + len(ps_vulns) + len(ws_vulns)

        if total_known > 0:
            console.print(
                f"\n[bold red]"
                f"WARNING: {total_known} known CVE(s) found — verify before investing research time"
                f"[/bold red]"
            )

        # Wordfence CVEs
        if existing_cves:
            console.print(f"\n  [bold yellow]Wordfence[/bold yellow] ({len(existing_cves)} CVE(s)):")
            for cve in existing_cves[:3]:
                title  = (cve.get("title") or "")[:65]
                pub    = (cve.get("published") or "")[:10]
                cve_id = cve.get("cve", "?")
                console.print(f"   [dim]{cve_id}[/dim] — {title} [dim]({pub})[/dim]")
            if len(existing_cves) > 3:
                console.print(f"   [dim]...and {len(existing_cves) - 3} more[/dim]")

        # Patchstack CVEs
        if ps_available and ps_vulns:
            console.print(
                f"\n  [bold magenta]Patchstack[/bold magenta] ({len(ps_vulns)} CVE(s))"
                f" [dim italic]— often ahead of Wordfence[/dim italic]:"
            )
            for v in ps_vulns[:3]:
                researcher = v.get("researcher", "Unknown")
                pub        = (v.get("published") or "")[:10]
                cve_id     = v.get("cve", "No CVE")
                title      = (v.get("title") or "")[:55]
                cvss       = v.get("cvss", "?")
                console.print(
                    f"   [dim]{cve_id}[/dim] — {title} "
                    f"[dim](CVSS {cvss}, {pub}, {researcher})[/dim]"
                )
            if len(ps_vulns) > 3:
                console.print(f"   [dim]...and {len(ps_vulns) - 3} more[/dim]")

        elif not ps_available and ps_reason == "no_api_token":
            console.print(
                "\n  [bold magenta]Patchstack[/bold magenta] "
                "[yellow]NO TOKEN — add PATCHSTACK_API_TOKEN to .env[/yellow]\n"
                "  [dim]Free at patchstack.com/register — "
                "this is the database benzdeus uses[/dim]"
            )

        elif ps_available and not ps_vulns:
            console.print(
                "\n  [bold magenta]Patchstack[/bold magenta] [green]Clean — no known CVEs[/green]"
            )

        if ws_vulns:
            console.print(f"\n  [bold cyan]WPScan[/bold cyan] ({len(ws_vulns)} CVE(s)):")
            for v in ws_vulns[:4]:
                console.print(
                    f"   [dim]{v.get('cve','No CVE')}[/dim] — "
                    f"{v.get('title','')[:60]} "
                    f"[dim](fixed: {v.get('fixed_in') or 'No fix'})[/dim]"
                )


        # ── Bounty estimates ───────────────────────────────────
        console.print("\nBounty Estimates (directional):")
        for vtype in ["csrf", "stored_xss", "rce", "auth_bypass"]:
            est = estimate_bounty(install_count, 9.0, vtype)
            console.print(f"  {vtype:<20} ~[green]${est['estimate']:,.0f}[/green]")

        # ── Final recommendation ───────────────────────────────
        has_any_cve = total_known > 0
        rec = _build_rec(any_in_scope, has_any_cve, closed)
        console.print(f"\n[bold]Recommendation:[/bold] {rec}\n")

    asyncio.run(_run())


# ── Scanner ────────────────────────────────────────────────────

@cli.command()
@click.argument("slug")
@click.option("--json-out",  is_flag=True, help="Output raw JSON")
@click.option("--show-hits", is_flag=True, help="Show all grep hits")
def scan(slug: str, json_out: bool, show_hits: bool):
    """Download and scan a plugin for CSRF/missing nonce vulnerabilities."""

    async def _run():
        slug_clean = slug.strip().lower()
        console.print(f"[bold blue]Scanning:[/bold blue] {slug_clean}")

        with Progress(SpinnerColumn(), TextColumn("[bold blue]Downloading & scanning..."), transient=True) as p:
            p.add_task("", total=None)
            results = await scan_plugin(slug_clean)

        if "error" in results:
            console.print(f"[bold red]Error:[/bold red] {results['message']}")
            return

        if json_out:
            click.echo(json.dumps(results, indent=2, default=str))
            return

        verdict    = results.get("verdict", "unknown")
        confidence = results.get("confidence", "none")
        v_color    = verdict_color(verdict)
        c_color    = confidence_color(confidence)

        console.print(Panel(
            f"[bold {v_color}]{verdict.upper().replace('_', ' ')}[/bold {v_color}]\n"
            f"Confidence: [{c_color}]{confidence.upper()}[/{c_color}]   "
            f"Files: {results['file_count']}   Hits: {results['hit_count']}   "
            f"Nonces: {results['nonce_hit_count']}   "
            f"Time: {results.get('duration_ms', 0)}ms",
            title=f"[bold]Scan Results — {slug_clean}[/bold]",
            border_style=v_color,
        ))

        signals = Table(box=box.SIMPLE, show_header=False)
        signals.add_column("Signal", style="dim")
        signals.add_column("Found")
        for key, label in [
            ("has_ajax_handlers",  "AJAX handlers (wp_ajax_*)"),
            ("has_admin_post",     "Admin POST handlers"),
            ("has_state_changes",  "State changes (update_option, wp_insert, etc)"),
            ("has_post_data",      "Raw $_POST/$_GET consumption"),
            ("has_nonces",         "Nonce protection detected"),
        ]:
            val      = results.get(key, False)
            is_nonce = key == "has_nonces"
            color    = ("green" if val else "dim") if is_nonce else ("red" if val else "green")
            signals.add_row(label, f"[{color}]{'YES' if val else 'NO'}[/{color}]")
        console.print(signals)

        top_hits = results.get("top_hits", [])
        if top_hits and show_hits:
            console.print("\n[bold]Top Suspicious Code Locations:[/bold]")
            for h in top_hits[:8]:
                console.print(f"  [cyan]{h['file']}:{h['line']}[/cyan]  [dim]{h['pattern']}[/dim]")
                console.print(f"    [dim]{h['snippet'][:120]}[/dim]")

        semgrep_findings = results.get("semgrep_findings", [])
        if semgrep_findings:
            console.print(f"\n[bold red]Semgrep — {len(semgrep_findings)} Finding(s)[/bold red]")
            high_threat = [f for f in semgrep_findings if f.get("is_high_threat")]
            if high_threat:
                console.print(f"[bold red]{len(high_threat)} HIGH THREAT finding(s)[/bold red]")
            for f in semgrep_findings[:5]:
                sev_color = {"high": "red", "medium": "yellow", "low": "cyan"}.get(f["severity"], "white")
                ht_badge  = " [red][HIGH THREAT][/red]" if f.get("is_high_threat") else ""
                console.print(
                    f"\n  [{sev_color}][{f['severity'].upper()}][/{sev_color}]{ht_badge} "
                    f"[bold]{f['vuln_class']}[/bold] — CVSS {f['cvss']}"
                )
                console.print(f"  [cyan]{f['file']}:{f['line_start']}[/cyan]")
                console.print(f"  [dim]{f['message'][:150]}[/dim]")
                if f.get("code_snippet"):
                    console.print(f"  [dim]Code: {f['code_snippet'][:100]}[/dim]")

        engines = results.get("engines", ["grep"])
        console.print(f"\n[dim]Engines used: {', '.join(engines)}[/dim]\n")

    asyncio.run(_run())


# ── Target Tracker ─────────────────────────────────────────────

@cli.group()
def targets():
    """Manage your bug bounty target pipeline."""
    pass


@targets.command("list")
@click.option("--status", default=None, help="Filter by status")
def targets_list(status: str):
    """List all tracked targets."""
    from backend.database import get_db
    db = get_db()

    q = db.table("targets").select("slug,name,status,priority,install_count,in_scope,updated_at")
    q = q.order("updated_at", desc=True)
    if status:
        q = q.eq("status", status)
    rows = q.execute().data

    if not rows:
        console.print("[dim]No targets tracked yet. Run: bountyscope scope <slug>[/dim]")
        return

    tbl = Table(box=box.ROUNDED, title="[bold]Target Pipeline[/bold]")
    tbl.add_column("Slug",     style="cyan bold")
    tbl.add_column("Name",     max_width=30)
    tbl.add_column("Installs", justify="right")
    tbl.add_column("In Scope", justify="center")
    tbl.add_column("Status")
    tbl.add_column("Priority")
    tbl.add_column("Updated")

    status_colors   = {
        "queued": "dim", "scanning": "blue", "reviewed": "yellow",
        "reported": "cyan", "paid": "green", "dismissed": "red",
    }
    priority_colors = {"high": "red", "medium": "yellow", "low": "dim"}

    for row in rows:
        sc      = scope_color(row.get("in_scope", False))
        st      = row.get("status", "queued")
        pr      = row.get("priority", "medium")
        updated = (row.get("updated_at") or "")[:10]
        tbl.add_row(
            row["slug"],
            (row.get("name") or row["slug"])[:30],
            f"{row.get('install_count') or 0:,}",
            f"[{sc}]{'✓' if row.get('in_scope') else '✗'}[/{sc}]",
            f"[{status_colors.get(st,'white')}]{st}[/{status_colors.get(st,'white')}]",
            f"[{priority_colors.get(pr,'white')}]{pr}[/{priority_colors.get(pr,'white')}]",
            updated,
        )
    console.print(tbl)


@targets.command("stats")
def targets_stats():
    """Show pipeline and bounty summary stats."""
    from backend.database import get_db
    db = get_db()

    tgts  = db.table("targets").select("status,in_scope,priority").execute().data
    finds = db.table("findings").select("status,severity,bounty_paid,bounty_estimate").execute().data

    total_paid     = sum(f.get("bounty_paid") or 0 for f in finds)
    total_estimate = sum(f.get("bounty_estimate") or 0 for f in finds)

    console.print(Panel(
        f"[bold]Targets:[/bold]  {len(tgts)} total  |  "
        f"{sum(1 for t in tgts if t.get('in_scope'))} in-scope\n"
        f"[bold]Findings:[/bold] {len(finds)} total  |  "
        f"{sum(1 for f in finds if f.get('status') == 'submitted')} submitted  |  "
        f"{sum(1 for f in finds if f.get('status') == 'accepted')} accepted\n"
        f"[bold]Bounties:[/bold] [green]${total_paid:,.2f}[/green] paid  |  "
        f"[yellow]${total_estimate:,.2f}[/yellow] estimated pipeline",
        title="[bold blue]BountyScope — Pipeline Stats[/bold blue]",
        border_style="blue",
    ))


@targets.command("update")
@click.argument("slug")
@click.option("--status",   help="queued|scanning|reviewed|reported|paid|dismissed")
@click.option("--priority", help="low|medium|high")
@click.option("--notes",    help="Notes text")
def targets_update(slug: str, status: str, priority: str, notes: str):
    """Update a target's status, priority, or notes."""
    from backend.database import get_db
    db = get_db()

    payload = {k: v for k, v in {"status": status, "priority": priority, "notes": notes}.items() if v}
    if not payload:
        console.print("[yellow]Nothing to update. Pass --status, --priority, or --notes.[/yellow]")
        return

    db.table("targets").update(payload).eq("slug", slug).execute()
    console.print(f"[green]Updated:[/green] {slug} → {payload}")


# ── Recommendation builder ─────────────────────────────────────

def _build_rec(in_scope: bool, has_cve: bool, closed: bool) -> str:
    if closed:
        return "[red]SKIP[/red] — Plugin is closed."
    if has_cve:
        return (
            "[yellow]CAUTION[/yellow] — Known CVEs exist in one or more databases. "
            "Verify your finding is not a duplicate before investing time."
        )
    if not in_scope:
        return "[red]OUT OF SCOPE[/red] — Below install threshold for your tier."
    return "[green]PROCEED[/green] — In scope, scan recommended."


if __name__ == "__main__":
    cli()
