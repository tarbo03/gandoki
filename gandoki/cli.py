"""Gandoki CLI."""
from __future__ import annotations
import asyncio
import json as _json
import os
import sys
import uuid

import click
from pathlib import Path

from . import __version__

from .config import load_config
from .ui.progress import make_progress
from .discovery.file_input import load_domains_file, merge_load_results
from .pipeline.orchestrator import run_scan
from .report.html_report import write_html
from .report.json_report import write_json
from .report.md_report import write_md
from .report.sarif import write_sarif
from .storage import db



_BANNER_ART_UNICODE = r"""
  ██████╗  █████╗ ███╗   ██╗██████╗  ██████╗ ██╗  ██╗██╗
 ██╔════╝ ██╔══██╗████╗  ██║██╔══██╗██╔═══██╗██║ ██╔╝██║
 ██║  ███╗███████║██╔██╗ ██║██║  ██║██║   ██║█████╔╝ ██║
 ██║   ██║██╔══██║██║╚██╗██║██║  ██║██║   ██║██╔═██╗ ██║
 ╚██████╔╝██║  ██║██║ ╚████║██████╔╝╚██████╔╝██║  ██╗██║
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝
"""


def _print_banner(*, quiet: bool = False) -> None:
    """Print the Gandoki banner (skipped on --quiet, non-TTY, or NO_COLOR)."""
    if quiet or os.environ.get("GANDOKI_QUIET") or os.environ.get("NO_COLOR"):
        return
    if not sys.stdout.isatty():
        return
    CYAN    = "\033[1;36m"
    DIM     = "\033[2m"
    MAGENTA = "\033[1;35m"
    RESET   = "\033[0m"
    click.echo(f"{CYAN}{_BANNER_ART_UNICODE}{RESET}")
    click.echo(f"{DIM}──────────────────────────────────────────────────────────────────{RESET}")
    click.echo(f"{CYAN}  Precision-first secret & debug-exposure scanner{RESET}")
    click.echo(f"{MAGENTA}  v{__version__}  ·  Author: Godwin Tarbo  ·  github.com/tarbo03{RESET}")
    click.echo(f"{DIM}──────────────────────────────────────────────────────────────────{RESET}")
    click.echo()



def _tier_badge(tier_str: str) -> str:
    """Colored tier badge for the post-scan summary."""
    palettes = {
        "VALIDATED_LIVE":    ("\033[1;37;41m", " LIVE "),
        "CONFIRMED_PARTIAL": ("\033[1;37;43m", " CONFIRMED "),
        "FORMAT_MATCH":      ("\033[1;30;47m", " FORMAT "),
        "SUSPECTED":         ("\033[2;37m",    " SUSPECTED "),
    }
    color, label = palettes.get(tier_str, ("", f" {tier_str} "))
    return f"{color}{label}\033[0m"


def _open_browser(path: str) -> None:
    """Best-effort open of a file in the system default application."""
    import subprocess
    import sys
    full_path = os.path.abspath(path)
    try:
        if sys.platform == "darwin":      # macOS
            subprocess.Popen(["open", full_path])
        elif sys.platform == "win32":     # Windows
            os.startfile(full_path)
        else:                             # Linux (xdg-open)
            subprocess.Popen(["xdg-open", full_path], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL)
    except Exception:
        # Fallback to webbrowser if xdg-open is missing
        try:
            import webbrowser
            webbrowser.open(f"file://{full_path}")
        except Exception:
            pass


def _handle_report_open(*, md_path, html_path, open_flag, quiet):
    """Decide which report(s) to open after a scan.

    - --open    -> open everything requested, no prompt
    - --no-open -> open nothing
    - -q/nonTTY -> open nothing
    - both formats requested -> prompt: markdown / html / both / none
    - single format requested -> open it (respects the flags above)
    """
    if quiet or open_flag is False:
        return
    if open_flag is True:
        if md_path:
            _open_browser(md_path)
        if html_path:
            _open_browser(html_path)
        return
    if not sys.stdout.isatty():
        return
    has_md = bool(md_path)
    has_html = bool(html_path)
    if not has_md and not has_html:
        return
    if has_md and not has_html:
        _open_browser(md_path)
        return
    if has_html and not has_md:
        _open_browser(html_path)
        return

    CYAN  = "\033[1;36m"
    DIM   = "\033[2m"
    RESET = "\033[0m"
    click.echo()
    click.echo(f"{DIM}  Report formats available:{RESET}")
    click.echo(f"    {CYAN}[1]{RESET} Markdown   {DIM}{md_path}{RESET}")
    click.echo(f"    {CYAN}[2]{RESET} HTML       {DIM}{html_path}{RESET}")
    click.echo(f"    {CYAN}[3]{RESET} Both")
    click.echo(f"    {CYAN}[4]{RESET} None")
    try:
        choice = click.prompt(
            "  Open which report", default="1",
            type=click.Choice(["1", "2", "3", "4"]),
            show_choices=False, show_default=True,
        )
    except (click.Abort, EOFError, KeyboardInterrupt):
        click.echo()
        return
    if choice in ("1", "3") and md_path:
        _open_browser(md_path)
    if choice in ("2", "3") and html_path:
        _open_browser(html_path)


def _print_scan_summary(result, *, job_id: str,
                        out_md: str | None = None,
                        out_html: str | None = None,
                        quiet: bool = False, force: bool = False) -> bool:
    """Post-scan summary. Returns True if printed, False if skipped."""
    if quiet:
        return False
    if not force and not sys.stdout.isatty():
        return False

    CYAN    = "\033[1;36m"
    GREEN   = "\033[1;32m"
    YELLOW  = "\033[1;33m"
    RED     = "\033[1;31m"
    MAGENTA = "\033[1;35m"
    DIM     = "\033[2m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    WIDTH   = 68
    bar = f"{CYAN}{'═' * WIDTH}{RESET}"

    cov = result.coverage_manifest or {}
    findings = result.findings or []

    accepted  = [f for f in findings if f.section.value == "ACCEPTED"]
    retracted = [f for f in findings if f.section.value == "RETRACTED"]

    tier_rank   = {"VALIDATED_LIVE": 4, "CONFIRMED_PARTIAL": 3,
                   "FORMAT_MATCH": 2, "SUSPECTED": 1}
    impact_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    accepted.sort(
        key=lambda f: -(tier_rank.get(f.tier.value, 0)
                        * impact_rank.get(f.impact.level.value, 0))
    )

    short = job_id[:12]

    print()
    print(bar)
    print(f"{CYAN}{BOLD}  SCAN COMPLETE{RESET}   {DIM}job {short}{RESET}")
    print(bar)
    print()

    print(f"{BOLD}  Coverage{RESET}")
    print(f"    domains       {cov.get('domains_scanned', 0)}")
    print(f"    pages         {cov.get('pages_fetched', 0)}")
    print(f"    assets        {cov.get('assets_scanned', 0)}")
    trunc = cov.get("assets_truncated_by_limit", 0)
    if trunc:
        print(f"    {YELLOW}truncated     {trunc} (config limit){RESET}")
    failed = cov.get("assets_failed", 0)
    if failed:
        print(f"    {YELLOW}failed        {failed}{RESET}")
    for reason, count in (cov.get("assets_skipped_reason") or {}).items():
        print(f"    {DIM}skipped/{reason} {count}{RESET}")
    print()

    print(f"{BOLD}  Results{RESET}")
    if not accepted and not retracted:
        print(f"    {GREEN}✓ No findings{RESET} — target appears clean")
        print(f"    {DIM}(based on {cov.get('pages_fetched', 0)} pages, "
              f"{cov.get('assets_scanned', 0)} assets){RESET}")
    else:
        print(f"    {DIM}── VERDICT ── SEVERITY ── FINDING ────────────────────────────{RESET}")
        for f in accepted[:10]:
            # Verdict logic
            if f.tier.value == "CONFIRMED_PARTIAL":
                v_text, v_color = "CONFIRMED", GREEN
            elif f.tier.value == "VALIDATED_LIVE":
                v_text, v_color = "VALIDATED", RED
            else:
                v_text, v_color = "FORMAT", YELLOW
                
            # Severity logic
            lvl = f.impact.level.value
            s_color = RED if lvl in ("CRITICAL", "HIGH") else YELLOW if lvl == "MEDIUM" else ""
            
            print(f"    {v_color}{v_text:<12}{RESET} {s_color}{lvl:<8}{RESET} {f.secret_type}")
            if f.impact.cap_reason:
                print(f"    {DIM}             └─ {f.impact.cap_reason[:60]}{RESET}")
                
        if len(accepted) > 10:
            print(f"    {DIM}... and {len(accepted) - 10} more (see report){RESET}")
            
        if retracted:
            print(f"\n    {MAGENTA}AI-RETRACTED: {len(retracted)}{RESET} {DIM}(visible in report, never hidden){RESET}")
        sup = cov.get("suppressed_suspected", 0)
        if sup:
            print(f"    {DIM}SUPPRESSED:   {sup} (SUSPECTED — --include-suspected to view){RESET}")
    print()

    if accepted:
        print(f"{BOLD}  Top findings{RESET}")
        for f in accepted[:5]:
            badge = _tier_badge(f.tier.value)
            lvl = f.impact.level.value
            color = RED if lvl in ("CRITICAL", "HIGH") \
                    else YELLOW if lvl == "MEDIUM" else DIM
            print(f"    {badge}  {color}{lvl:<8}{RESET}  {f.secret_type}")
            url = f.evidence.asset_url
            if len(url) > 62:
                url = "…" + url[-61:]
            print(f"    {DIM}{url}{RESET}")
            if f.impact.cap_reason:
                print(f"    {DIM}cap: {f.impact.cap_reason[:78]}{RESET}")
            print()
        if len(accepted) > 5:
            print(f"    {DIM}… and {len(accepted) - 5} more (see report){RESET}")
            print()

    # Always show AI status — a defender needs to know whether AI ran,
    # was skipped, or failed. "Off" is different from "crashed".
    if cov.get("ai_enabled"):
        print(f"{BOLD}  AI{RESET}")
        print(f"    backend       {cov.get('ai_backend') or '—'}")
        print(f"    privacy       {cov.get('privacy_mode') or '—'}")
        fail = cov.get('ai_failures', 0)
        fail_color = YELLOW if fail else ""
        print(f"    failures      {fail_color}{fail}{RESET}")
        print()
    else:
        print(f"{BOLD}  AI{RESET}")
        reason = cov.get("ai_disabled_reason") or "not enabled"
        requested = cov.get("ai_requested", False)
        if requested:
            # User asked for AI but it didn't come up — this is important
            print(f"    {YELLOW}off — {reason}{RESET}")
        else:
            print(f"    {DIM}off — {reason}{RESET}")
        print()

    print(bar)
    print(f"{BOLD}  Next{RESET}")
    print(f"    {CYAN}gandoki show {short}{RESET}         "
          f"{DIM}# full findings{RESET}")
    if out_md:
        print(f"    {CYAN}open {out_md}{RESET}                "
              f"{DIM}# markdown report{RESET}")
    if out_html:
        print(f"    {CYAN}open {out_html}{RESET}                "
              f"{DIM}# HTML report{RESET}")
    print(f"    {CYAN}gandoki diff <prev> {short}{RESET}   "
          f"{DIM}# compare runs{RESET}")
    print(bar)
    print()
    return True


@click.group()
def cli():
    """Gandoki — precision-first secret & debug-exposure scanner."""


@cli.command()
@click.option("--scope", type=click.Path(exists=True),
              help="Authorized scope YAML")
@click.option("--domains", help="Comma-separated domains")
@click.option("--domains-file", "domains_files", multiple=True,
              type=click.Path(exists=True),
              help="CSV/TXT file of domains. Can be passed multiple times.")
@click.option("--url", "url_single", default=None,
              help="Single URL to scan (preserves path)")
@click.option("--max-domains", type=int, default=None,
              help="Override max_domains_per_run")
@click.option("--unlimited-domains", is_flag=True,
              help="Scan all provided domains (records in coverage)")
@click.option("--ignore-robots", is_flag=True,
              help="Ignore robots.txt (recorded in coverage)")
@click.option("--config", "config_path", default="config/config.yaml")
@click.option("--rules", "rules_path", default="config/rules.yaml")
@click.option("--severity-caps", "caps_path",
              default="config/severity_caps.yaml")
@click.option("--out", default="findings.json")
@click.option("--md", "md_out", default=None,
              help="Write a Markdown report (auto-opens unless --no-open)")
@click.option("--html", "html_out", default=None,
              help="Write an HTML report (use --open to auto-open)")
@click.option("--sarif", "sarif_out", default=None)
@click.option("--include-suspected", is_flag=True)
@click.option("--ai-enabled/--no-ai", "ai_override", default=None,
              help="Override ai.enabled from config")
@click.option("--quiet", "-q", is_flag=True, help="Suppress ASCII banner and summary")
@click.option("--summary-always", is_flag=True,
              help="Print summary even when piped (default: skip on non-TTY)")
@click.option("--open/--no-open", "open_report", default=None,
              help="Open HTML report in browser (default: yes when --html given)")
@click.option("--ai-backend", default=None,
              help="Override ai.backend (openrouter|ollama)")
def scan(scope, domains, domains_files, url_single, max_domains,
         unlimited_domains, ignore_robots, config_path, rules_path,
         caps_path, out, md_out, html_out, sarif_out, include_suspected,
         ai_override, ai_backend, quiet, open_report, summary_always):
    """Run a scan against authorized targets or a provided domain list."""
    _print_banner(quiet=quiet)
    cfg = load_config(config_path)

    # Default report: if user didn't specify --md, --html, or --sarif, write
    # a markdown report derived from --out (or "gandoki-report.md" if --out
    # isn't set). Only in interactive TTY sessions — CI/non-TTY stays JSON-only.
    if not md_out and not html_out and not sarif_out:
        if sys.stdout.isatty():
            md_out = str(Path(out).with_suffix(".md")) if out else "gandoki-report.md"

    file_domains: list[str] = []
    if domains_files:
        results = [load_domains_file(fp) for fp in domains_files]
        merged = merge_load_results(results)
        for r in results:
            click.echo(
                f"[{r.source_file}] {len(r.domains)} unique domains "
                f"(skipped invalid: {len(r.skipped_invalid)}, "
                f"duplicates: {r.skipped_duplicates})"
            )
            if r.skipped_invalid[:5]:
                click.echo(f"    sample skipped: {r.skipped_invalid[:5]}")
        file_domains = merged.domains

    if not (scope or domains or file_domains or url_single):
        click.echo(
            "error: provide at least one of --scope, --domains, "
            "--domains-file, or --url",
            err=True,
        )
        raise SystemExit(2)

    job_id = uuid.uuid4().hex
    db.create_job(cfg["db_path"], job_id, {
        "scope": scope,
        "domains": domains,
        "domains_files": list(domains_files),
        "url": url_single,
        "include_suspected": include_suspected,
    })

    click.echo(f"[job {job_id}] starting scan...")
    try:
        progress = make_progress(quiet=quiet)
        with progress:
            result = asyncio.run(run_scan(
                cfg=cfg, rules_path=rules_path, caps_path=caps_path,
                scope=scope, domains=domains, extra_domains=file_domains,
                url_single=url_single,
                include_suspected=include_suspected,
                ignore_robots=ignore_robots,
                max_domains_override=max_domains,
                unlimited_domains=unlimited_domains,
                ai_override_enabled=ai_override,
                ai_override_backend=ai_backend,
                progress=progress,
            ))
    except Exception as e:
        db.update_job_status(cfg["db_path"], job_id, "error",
                             error=f"{type(e).__name__}: {e}")
        click.echo(f"error: {type(e).__name__}: {e}", err=True)
        raise SystemExit(1)

    write_json(result.findings, out, include_suspected=include_suspected,
               coverage_manifest=result.coverage_manifest)
    click.echo(f"Wrote {out} "
               f"({result.coverage_manifest['accepted']} accepted, "
               f"{result.coverage_manifest['retracted_by_ai']} retracted)")

    if md_out:
        write_md(result.findings, md_out,
                 include_suspected=include_suspected,
                 coverage_manifest=result.coverage_manifest)
        click.echo(f"Wrote {md_out}")
    if html_out:
        write_html(result.findings, html_out,
                   include_suspected=include_suspected,
                   coverage_manifest=result.coverage_manifest)
        click.echo(f"Wrote {html_out}")
    if sarif_out:
        write_sarif(result.findings, sarif_out,
                    include_suspected=include_suspected,
                    coverage_manifest=result.coverage_manifest)
        click.echo(f"Wrote {sarif_out}")

    # persist findings for history / diff
    from .report.json_report import build_report
    report = build_report(result.findings, include_suspected=include_suspected,
                          coverage_manifest=result.coverage_manifest)
    rows = report["findings"] + report["retracted"]
    db.save_findings(cfg["db_path"], job_id, rows)
    db.update_job_status(
        cfg["db_path"], job_id, "done",
        summary={
            "accepted": len(report["findings"]),
            "retracted": len(report["retracted"]),
            "domains_scanned": result.domains_scanned,
        },
        coverage=result.coverage_manifest,
    )
    printed = _print_scan_summary(result, job_id=job_id,
                                  out_md=md_out, out_html=html_out,
                                  quiet=quiet, force=summary_always)
    if not printed:
        click.echo(f"[job {job_id}] done. View: gandoki show {job_id}")

    _handle_report_open(
        md_path=md_out,
        html_path=html_out,
        open_flag=open_report,
        quiet=quiet,
    )


@cli.command()
@click.option("--config", "config_path", default="config/config.yaml")
@click.option("--limit", default=20, type=int)
def history(config_path, limit):
    """List recent scan jobs."""
    cfg = load_config(config_path)
    jobs = db.list_jobs(cfg["db_path"], limit=limit)
    if not jobs:
        click.echo("no jobs yet")
        return
    for j in jobs:
        summary = j.get("summary") or {}
        click.echo(
            f"{j['job_id'][:12]}  {j['status']:8s}  "
            f"accepted={summary.get('accepted', '?'):>3}  "
            f"retracted={summary.get('retracted', '?'):>3}  "
            f"{j['created_at']}"
        )


@cli.command()
@click.argument("job_id")
@click.option("--config", "config_path", default="config/config.yaml")
@click.option("--raw", is_flag=True, help="Emit raw JSON")
def show(job_id, config_path, raw):
    """Show a single job's findings."""
    cfg = load_config(config_path)
    job = db.get_job(cfg["db_path"], job_id)
    if not job:
        click.echo(f"job not found: {job_id}", err=True)
        raise SystemExit(1)
    findings = db.get_findings(cfg["db_path"], job_id)
    payload = {**job, "findings": findings}
    if raw:
        click.echo(_json.dumps(payload, indent=2, default=str))
        return
    click.echo(f"Job:     {job['job_id']}")
    click.echo(f"Status:  {job['status']}")
    click.echo(f"Created: {job['created_at']}")
    if job.get("summary"):
        click.echo(f"Summary: {_json.dumps(job['summary'])}")
    click.echo("")
    accepted = [f for f in findings if f["section"] == "ACCEPTED"]
    retracted = [f for f in findings if f["section"] == "RETRACTED"]
    click.echo(f"Accepted: {len(accepted)}")
    for f in accepted[:50]:
        click.echo(f"  {f['tier']:<20} {f['secret_type']:<22} "
                   f"{f['impact']['level']:<9} {f['evidence']['asset_url']}")
    if retracted:
        click.echo(f"\nRetracted: {len(retracted)}")
        for f in retracted[:20]:
            reason = (f.get("retraction") or {}).get("reason", "?")
            click.echo(f"  {f['tier']:<20} {f['secret_type']:<22} — {reason}")


@cli.command()
@click.argument("job_a")
@click.argument("job_b")
@click.option("--config", "config_path", default="config/config.yaml")
@click.option("--raw", is_flag=True)
def diff(job_a, job_b, config_path, raw):
    """Compare ACCEPTED findings between two jobs (job_a → job_b)."""
    cfg = load_config(config_path)
    try:
        result = db.diff_jobs(cfg["db_path"], job_a, job_b)
    except ValueError as e:
        click.echo(f"error: {e}", err=True)
        raise SystemExit(1)
    if raw:
        click.echo(_json.dumps(result, indent=2, default=str))
        return
    s = result["summary"]
    click.echo(f"{job_a[:12]} → {job_b[:12]}")
    click.echo(f"  NEW:        {s['new_count']}")
    click.echo(f"  FIXED:      {s['fixed_count']}")
    click.echo(f"  PERSISTING: {s['persisting_count']}")
    if s["new_count"]:
        click.echo("\nNew findings:")
        for f in result["new"][:20]:
            click.echo(f"  {f['secret_type']:<22} {f['evidence']['asset_url']}")


@cli.command()
def version():
    """Print version, author, repo."""
    _print_banner()
    click.echo(f"Gandoki v{__version__}")
    click.echo("Author: Godwin Tarbo")
    click.echo("Repo:   https://github.com/tarbo03/gandoki")


if __name__ == "__main__":
    cli()
