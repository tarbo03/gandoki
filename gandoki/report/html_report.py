"""Self-contained HTML report with a cybersecurity-themed dark UI."""
from __future__ import annotations
import html
from datetime import datetime, timezone

from ..models import ConfidenceTier, Finding, Section


_TIER_CLASS = {
    "VALIDATED_LIVE": "tier-validated",
    "CONFIRMED_PARTIAL": "tier-confirmed",
    "FORMAT_MATCH": "tier-format",
    "SUSPECTED": "tier-suspected",
}

_IMPACT_CLASS = {
    "CRITICAL": "impact-critical",
    "HIGH": "impact-high",
    "MEDIUM": "impact-medium",
    "LOW": "impact-low",
    "INFO": "impact-info",
}


def _row(f: Finding, *, retracted: bool) -> str:
    tier_cls = _TIER_CLASS.get(f.tier.value, "")
    impact_cls = _IMPACT_CLASS.get(f.impact.level.value, "")
    cap_html = (f'<div class="cap-reason">{html.escape(f.impact.cap_reason)}</div>'
                if f.impact.cap_reason else "")
    snippet = html.escape(f._redact(f.evidence.matched_snippet))
    reason_html = ""
    if retracted and f.retraction:
        reason_html = (
            f"<td><strong>Retraction:</strong> {html.escape(f.retraction.reason)}<br>"
            f"<span class=\"retraction-meta\">by {html.escape(f.retraction.decided_by)}</span></td>"
        )
    return f"""
        <tr>
          <td><span class="tier-badge {tier_cls}">{html.escape(f.tier.value)}</span></td>
          <td><code>{html.escape(f.secret_type)}</code></td>
          <td><span class="{impact_cls}">{html.escape(f.impact.level.value)}</span>{cap_html}</td>
          <td><code class="snippet">{snippet}</code></td>
          <td>{html.escape(f.validation.status.value)}</td>
          <td class="url-cell">{html.escape(f.evidence.asset_url)}</td>
          <td><code class="dim">{html.escape(f.evidence.provenance.value)}</code></td>
          <td>{html.escape(f.cluster_id or "—")}</td>
          {reason_html}
        </tr>"""


def write_html(findings: list[Finding], path: str, *,
               include_suspected: bool = False,
               coverage_manifest: dict | None = None) -> None:
    accepted: list[Finding] = []
    retracted: list[Finding] = []
    for f in findings:
        if f.tier == ConfidenceTier.KNOWN_PUBLIC:
            continue
        if f.tier == ConfidenceTier.SUSPECTED and not include_suspected:
            continue
        (retracted if f.section == Section.RETRACTED else accepted).append(f)

    impact_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    tier_rank = {"VALIDATED_LIVE": 4, "CONFIRMED_PARTIAL": 3,
                 "FORMAT_MATCH": 2, "SUSPECTED": 1}
    accepted.sort(key=lambda f: -(
        impact_rank.get(f.impact.level.value, 0)
        * tier_rank.get(f.tier.value, 0)
    ))

    accepted_rows = "".join(_row(f, retracted=False) for f in accepted)
    retracted_rows = "".join(_row(f, retracted=True) for f in retracted)
    cov = coverage_manifest or {}
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if accepted or retracted:
        findings_block = f"""
    <h2>Accepted findings <span class="count">{len(accepted)}</span></h2>
    <table>
      <thead>
        <tr>
          <th>Tier</th><th>Type</th><th>Impact</th><th>Snippet</th>
          <th>Validation</th><th>Asset</th><th>Provenance</th>
          <th>Cluster</th>
        </tr>
      </thead>
      <tbody>{accepted_rows or '<tr><td colspan="8" class="empty">None</td></tr>'}</tbody>
    </table>
    <h2 class="retracted">Retracted by AI adjudicator <span class="count">{len(retracted)}</span></h2>
    <p class="note">Visible for review. Retraction is not hiding — every entry has a reason.</p>
    <table>
      <thead>
        <tr>
          <th>Tier</th><th>Type</th><th>Impact</th><th>Snippet</th>
          <th>Validation</th><th>Asset</th><th>Provenance</th>
          <th>Cluster</th><th>Reason</th>
        </tr>
      </thead>
      <tbody>{retracted_rows or '<tr><td colspan="9" class="empty">0 retracted</td></tr>'}</tbody>
    </table>
        """
    else:
        findings_block = """
    <div class="empty-state">
      <strong>✓ No findings</strong> — target appears clean.<br>
      Coverage: {pages} pages · {assets} assets scanned.
    </div>
        """.format(pages=cov.get("pages_fetched", 0),
                   assets=cov.get("assets_scanned", 0))

    manifest_rows = ""
    for k, v in cov.items():
        if isinstance(v, dict):
            v = ", ".join(f"{kk}: {vv}" for kk, vv in v.items()) or "—"
        manifest_rows += f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>"

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gandoki Scan Report — {ts}</title>
<style>
  :root {{
    --bg-deep: #050810; --bg-mid: #0a0f1f; --bg-panel: #0f1524;
    --bg-hover: #161e33; --border: #1a2540;
    --text: #d0d8e8; --text-dim: #7a869c;
    --cyan: #00e5c0; --blue: #4d9eff; --magenta: #ff4dbb;
    --red: #ff3b5c; --orange: #ff9f45; --yellow: #ffd93d;
    --green: #4ade80;
    --mono: 'SF Mono','Monaco','Menlo','Consolas',monospace;
    --sans: -apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{
    margin: 0; padding: 0; background: var(--bg-deep);
    color: var(--text); font-family: var(--sans); font-size: 14px;
    line-height: 1.5; min-height: 100vh;
  }}
  body {{
    background-image:
      radial-gradient(ellipse at 15% 8%,  rgba(0,229,192,0.10), transparent 45%),
      radial-gradient(ellipse at 85% 92%, rgba(77,158,255,0.10), transparent 45%),
      radial-gradient(ellipse at 50% 50%, rgba(255,77,187,0.03), transparent 60%),
      linear-gradient(rgba(0,229,192,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,229,192,0.03) 1px, transparent 1px);
    background-size: 100% 100%,100% 100%,100% 100%,32px 32px,32px 32px;
    background-attachment: fixed;
  }}
  .container {{ max-width: 1240px; margin: 0 auto; padding: 40px 24px 60px; }}
  header {{
    border-bottom: 1px solid var(--border);
    padding-bottom: 24px; margin-bottom: 28px; position: relative;
  }}
  header::before {{
    content: ''; position: absolute; left: 0; bottom: -1px;
    width: 120px; height: 2px;
    background: linear-gradient(90deg, var(--cyan), transparent);
  }}
  .brand {{
    font-family: var(--mono); font-size: 11px; color: var(--cyan);
    letter-spacing: 4px; text-transform: uppercase; margin-bottom: 10px; opacity: 0.85;
  }}
  h1 {{
    font-family: var(--mono); font-size: 26px; font-weight: 500;
    margin: 0 0 10px; letter-spacing: -0.5px;
  }}
  .subtitle {{ color: var(--text-dim); font-family: var(--mono); font-size: 13px; }}
  .subtitle a {{ color: var(--cyan); text-decoration: none; }}
  .stat-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr));
    gap: 12px; margin-bottom: 32px;
  }}
  .stat {{
    background: var(--bg-panel); border: 1px solid var(--border);
    border-radius: 6px; padding: 16px; position: relative; overflow: hidden;
  }}
  .stat::before {{
    content: ''; position: absolute; top: 0; left: 0;
    width: 3px; height: 100%; background: var(--cyan); opacity: 0.4;
  }}
  .stat-label {{
    font-family: var(--mono); font-size: 10px; color: var(--text-dim);
    text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 6px;
  }}
  .stat-value {{ font-family: var(--mono); font-size: 22px; font-weight: 600; }}
  .stat-value.warn {{ color: var(--yellow); }}
  .stat-value.bad  {{ color: var(--red); }}
  .stat-value.good {{ color: var(--green); }}
  h2 {{
    font-family: var(--mono); font-size: 14px; font-weight: 500;
    color: var(--cyan); text-transform: uppercase; letter-spacing: 2px;
    margin: 36px 0 14px; display: flex; align-items: center; gap: 12px;
  }}
  h2::before {{
    content: ''; width: 4px; height: 14px; background: var(--cyan);
    box-shadow: 0 0 12px var(--cyan);
  }}
  h2.retracted {{ color: var(--magenta); }}
  h2.retracted::before {{ background: var(--magenta); box-shadow: 0 0 12px var(--magenta); }}
  .count {{
    font-size: 11px; color: var(--text-dim);
    background: var(--bg-panel); padding: 2px 8px; border-radius: 10px;
    border: 1px solid var(--border); font-weight: normal;
  }}
  .note {{ color: var(--text-dim); font-size: 12px; margin: -6px 0 14px; }}
  table {{
    width: 100%; border-collapse: collapse; background: var(--bg-panel);
    border: 1px solid var(--border); border-radius: 6px; overflow: hidden;
    font-family: var(--mono); font-size: 11.5px; margin-bottom: 24px;
  }}
  thead {{ background: var(--bg-mid); }}
  th {{
    text-align: left; padding: 12px 14px; font-weight: 500;
    color: var(--cyan); font-size: 10px; text-transform: uppercase;
    letter-spacing: 1px; border-bottom: 1px solid var(--border);
  }}
  td {{ padding: 12px 14px; border-top: 1px solid var(--border); vertical-align: top; }}
  tbody tr:hover {{ background: var(--bg-hover); }}
  .url-cell {{ word-break: break-all; max-width: 320px; }}
  code, .snippet {{
    font-family: var(--mono); font-size: 11px; background: var(--bg-deep);
    padding: 2px 6px; border-radius: 3px; color: var(--cyan);
    word-break: break-all; display: inline-block;
  }}
  code.dim {{ color: var(--text-dim); }}
  .tier-badge {{
    display: inline-block; font-family: var(--mono); font-size: 10px;
    font-weight: 600; letter-spacing: 1px; padding: 3px 8px;
    border-radius: 3px; text-transform: uppercase; white-space: nowrap;
  }}
  .tier-validated {{ background: rgba(255,59,92,0.15);  color: var(--red);    border: 1px solid rgba(255,59,92,0.4); }}
  .tier-confirmed {{ background: rgba(255,159,69,0.15); color: var(--orange); border: 1px solid rgba(255,159,69,0.4); }}
  .tier-format    {{ background: rgba(255,217,61,0.12); color: var(--yellow); border: 1px solid rgba(255,217,61,0.35); }}
  .tier-suspected {{ background: rgba(122,134,156,0.12); color: var(--text-dim); border: 1px solid rgba(122,134,156,0.3); }}
  .impact-critical {{ color: var(--red);    font-weight: 600; }}
  .impact-high     {{ color: var(--orange); font-weight: 600; }}
  .impact-medium   {{ color: var(--yellow); }}
  .impact-low      {{ color: var(--text-dim); }}
  .impact-info     {{ color: var(--blue); }}
  .cap-reason {{ font-size: 10px; color: var(--text-dim); margin-top: 4px; font-style: italic; }}
  .retraction-meta {{ font-size: 10px; color: var(--text-dim); }}
  .empty-state {{
    background: var(--bg-panel); border: 1px solid var(--border);
    border-left: 3px solid var(--green); border-radius: 6px;
    padding: 24px; margin-bottom: 32px; color: var(--text-dim);
    font-family: var(--mono); line-height: 1.7;
  }}
  .empty-state strong {{ color: var(--green); }}
  .empty {{ color: var(--text-dim); text-align: center; padding: 20px; }}
  details {{ margin-top: 24px; }}
  details summary {{
    cursor: pointer; font-family: var(--mono); font-size: 12px;
    color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px;
    padding: 8px 0; user-select: none;
  }}
  details summary:hover {{ color: var(--cyan); }}
  footer {{
    border-top: 1px solid var(--border); padding-top: 24px;
    margin-top: 60px; color: var(--text-dim); font-family: var(--mono);
    font-size: 12px; display: flex; justify-content: space-between;
    flex-wrap: wrap; gap: 12px;
  }}
  footer a {{ color: var(--cyan); text-decoration: none; }}
  footer a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">// GANDOKI · SCAN REPORT</div>
    <h1>Security Findings</h1>
    <div class="subtitle">
      {ts} · by <a href="https://github.com/tarbo03">Godwin Tarbo</a> ·
      <a href="https://github.com/tarbo03/gandoki">github.com/tarbo03/gandoki</a>
    </div>
  </header>

  <div class="stat-grid">
    <div class="stat"><div class="stat-label">Domains</div><div class="stat-value">{cov.get('domains_scanned', 0)}</div></div>
    <div class="stat"><div class="stat-label">Pages</div><div class="stat-value">{cov.get('pages_fetched', 0)}</div></div>
    <div class="stat"><div class="stat-label">Assets</div><div class="stat-value">{cov.get('assets_scanned', 0)}</div></div>
    <div class="stat"><div class="stat-label">Accepted</div><div class="stat-value {'bad' if accepted else 'good'}">{len(accepted)}</div></div>
    <div class="stat"><div class="stat-label">Retracted</div><div class="stat-value warn">{len(retracted)}</div></div>
    <div class="stat"><div class="stat-label">AI</div><div class="stat-value" style="font-size:14px">{'on' if cov.get('ai_enabled') else 'off'}</div></div>
  </div>

  {findings_block}

  <details>
    <summary>Coverage manifest — full detail</summary>
    <table>
      <thead><tr><th>Key</th><th>Value</th></tr></thead>
      <tbody>{manifest_rows}</tbody>
    </table>
  </details>

  <footer>
    <div>Gandoki v1.0.0 · secret scanner that can't lie to you</div>
    <div><a href="https://github.com/tarbo03/gandoki">github.com/tarbo03/gandoki</a></div>
  </footer>
</div>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(doc)
