"""Minimal read-only dashboard over the FR-014 API.

Deliberately minimal, per locked decision #7: the API is the product, the
dashboard is a convenience for humans. Two pages — the campaign list and
a single campaign's candidate comparison — rendered as static HTML that
fetches from the `/v1` endpoints with the browser's own credentials. No
write affordances: approvals and releases happen through the API (or the
`evo` CLI), never through a button here.
"""

from __future__ import annotations

from html import escape

from fastapi import APIRouter, FastAPI
from fastapi.responses import HTMLResponse

router = APIRouter(include_in_schema=False)

_PAGE_STYLE = """
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a2e; }
    h1 { font-size: 1.4rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
    table { border-collapse: collapse; margin-top: 0.5rem; width: 100%; }
    th, td { border: 1px solid #d8d8e8; padding: 0.35rem 0.6rem; text-align: left;
             font-size: 0.85rem; }
    th { background: #f0f0f8; }
    code { font-size: 0.75rem; }
    .phase { font-weight: 600; }
    .gain { color: #0a7d33; } .regression { color: #b3261e; }
    dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.2rem 1rem; }
    dt { font-weight: 600; } dd { margin: 0; }
    section { margin-bottom: 2rem; }
  </style>
"""

_CAMPAIGN_LIST_BODY = """
  <h1>EvoRuntime campaigns</h1>
  <table id="campaigns">
    <thead><tr><th>Campaign</th><th>Name</th><th>Phase</th><th>Spec digest</th></tr></thead>
    <tbody></tbody>
  </table>
  <script>
    fetch('/v1/campaigns').then(r => r.json()).then(rows => {
      const tbody = document.querySelector('#campaigns tbody');
      for (const c of rows) {
        const tr = document.createElement('tr');
        const link = `<a href="/dashboard/campaigns/${c.campaign_id}">${c.campaign_id}</a>`;
        tr.innerHTML = `<td>${link}</td><td>${c.name}</td>` +
          `<td class="phase">${c.phase}</td><td><code>${c.spec_digest}</code></td>`;
        tbody.appendChild(tr);
      }
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="4">No campaigns yet.</td></tr>';
      }
    });
  </script>
"""


def _campaign_detail_body(campaign_id: str) -> str:
    safe_id = escape(campaign_id, quote=True)
    return f"""
  <h1>Campaign <code>{safe_id}</code></h1>
  <section id="summary"><h2>Summary</h2><dl></dl></section>
  <section id="candidates"><h2>Candidates</h2><table>
    <thead><tr><th>Candidate</th><th>Strategy</th><th>Status</th><th>Parent</th></tr></thead>
    <tbody></tbody></table></section>
  <section id="pareto"><h2>Comparison vs parent (gains / regressions / costs)</h2><table>
    <thead><tr><th>Candidate</th><th>Outcome</th><th>Gains</th><th>Regressions</th>
    <th>Costs</th></tr></thead><tbody></tbody></table></section>
  <section id="archive"><h2>Pareto archive across slices</h2><table>
    <thead><tr><th>Artifact</th><th>On frontier</th><th>Success</th><th>Mean costs</th>
    <th>Dominated by</th></tr></thead><tbody></tbody></table>
    <h2>Slices</h2><table>
    <thead><tr><th>Dimension</th><th>Value</th><th>Attestations</th><th>Success rate</th>
    <th>Mean costs</th></tr></thead><tbody></tbody></table></section>
  <section id="evidence"><h2>Evidence</h2><table>
    <thead><tr><th>Bundle</th><th>Artifact</th><th>Items</th></tr></thead>
    <tbody></tbody></table></section>
  <section id="approvals"><h2>Approvals</h2><table>
    <thead><tr><th>Candidate</th><th>Decision</th><th>Actor</th><th>Reason</th></tr></thead>
    <tbody></tbody></table></section>
  <section id="releases"><h2>Release state</h2><table>
    <thead><tr><th>Manifest</th><th>Status</th><th>Prior</th></tr></thead>
    <tbody></tbody></table></section>
  <script>
    const campaignId = '{safe_id}';
    const fmt = obj => Object.entries(obj).map(
      ([k, v]) => `<span class="${{v > 0 ? 'gain' : 'regression'}}">${{k}}: ${{v}}</span>`
    ).join(', ') || '—';
    fetch(`/v1/campaigns/${{campaignId}}`).then(r => r.json()).then(c => {{
      document.querySelector('#summary dl').innerHTML =
        `<dt>Phase</dt><dd class="phase">${{c.phase}}</dd>` +
        `<dt>Candidates</dt><dd>${{c.candidate_count}}</dd>` +
        `<dt>Spec digest</dt><dd><code>${{c.spec_digest}}</code></dd>`;
    }});
    fetch(`/v1/candidates?campaign_id=${{campaignId}}`).then(r => r.json()).then(rows => {{
      const tbody = document.querySelector('#candidates tbody');
      tbody.innerHTML = rows.map(c =>
        `<tr><td><code>${{c.proposal_id}}</code></td><td>${{c.strategy_id}}</td>` +
        `<td>${{c.status ?? '—'}}</td><td><code>${{c.parent_digest ?? '—'}}</code></td></tr>`
      ).join('') || '<tr><td colspan="4">No candidates.</td></tr>';
    }});
    fetch(`/v1/campaigns/${{campaignId}}/pareto`).then(r => r.json()).then(report => {{
      const tbody = document.querySelector('#pareto tbody');
      tbody.innerHTML = report.entries.map(e =>
        `<tr><td><code>${{e.proposal_id}}</code></td><td>${{e.outcome ?? 'unevaluated'}}</td>` +
        `<td>${{fmt(e.gains)}}</td><td>${{fmt(e.regressions)}}</td><td>${{fmt(e.costs)}}</td></tr>`
      ).join('') || '<tr><td colspan="5">No candidates.</td></tr>';
    }});
    fetch(`/v1/campaigns/${{campaignId}}/pareto-archive`).then(r => r.json()).then(report => {{
      const frontier = document.querySelector('#archive tbody');
      frontier.innerHTML = report.frontier.map(e =>
        `<tr><td><code>${{e.artifact_digest}}</code></td>` +
        `<td class="${{e.on_frontier ? 'gain' : 'regression'}}">${{e.on_frontier}}</td>` +
        `<td>${{e.success_rate === null ? '—' : (e.success_rate * 100).toFixed(0) + '%'}}</td>` +
        `<td>${{fmt(e.mean_costs)}}</td>` +
        `<td>${{e.dominated_by.map(d => `<code>${{d}}</code>`).join(', ') || '—'}}</td></tr>`
      ).join('') || '<tr><td colspan="5">No evaluated artifacts.</td></tr>';
      const slices = document.querySelectorAll('#archive tbody')[1];
      slices.innerHTML = report.slices.map(s =>
        `<tr><td>${{s.dimension}}</td><td>${{s.value}}</td>` +
        `<td>${{s.attestation_count}}</td>` +
        `<td>${{s.success_rate === null ? '—' : (s.success_rate * 100).toFixed(0) + '%'}}</td>` +
        `<td>${{fmt(s.mean_costs)}}</td></tr>`
      ).join('') || '<tr><td colspan="5">No slice annotations.</td></tr>';
      if (!report.reconciled) {{
        const warn = document.createElement('p');
        warn.className = 'regression';
        warn.textContent = `Archive drift detected: ${{report.drift.length}} discrepancy(ies).`;
        document.querySelector('#archive').prepend(warn);
      }}
    }});
    fetch(`/v1/evidence?campaign_id=${{campaignId}}`).then(r => r.json()).then(rows => {{
      const tbody = document.querySelector('#evidence tbody');
      tbody.innerHTML = rows.map(b =>
        `<tr><td><code>${{b.bundle_id}}</code></td>` +
        `<td><code>${{b.artifact_digest ?? '—'}}</code></td>` +
        `<td>${{b.redacted_items.length}}</td></tr>`
      ).join('') || '<tr><td colspan="3">No evidence bundles.</td></tr>';
    }});
    fetch(`/v1/campaigns/${{campaignId}}/approvals`).then(r => r.json()).then(rows => {{
      const tbody = document.querySelector('#approvals tbody');
      tbody.innerHTML = rows.map(a =>
        `<tr><td><code>${{a.proposal_id}}</code></td><td class="phase">${{a.kind}}</td>` +
        `<td>${{a.actor_identity}}</td><td>${{a.reason ?? '—'}}</td></tr>`
      ).join('') || '<tr><td colspan="4">No approval decisions.</td></tr>';
    }});
    fetch('/v1/releases').then(r => r.json()).then(rows => {{
      const tbody = document.querySelector('#releases tbody');
      tbody.innerHTML = rows.map(r =>
        `<tr><td><code>${{r.manifest_digest}}</code></td>` +
        `<td class="phase">${{r.status ?? '—'}}</td>` +
        `<td><code>${{r.prior_release_digest ?? '—'}}</code></td></tr>`
      ).join('') || '<tr><td colspan="3">No releases.</td></tr>';
    }});
  </script>
"""


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_home() -> HTMLResponse:
    """Campaign list — the dashboard's entry page."""
    return HTMLResponse(
        "<!doctype html><html><head><title>EvoRuntime</title>"
        f"{_PAGE_STYLE}</head><body>{_CAMPAIGN_LIST_BODY}</body></html>"
    )


@router.get("/dashboard/campaigns/{campaign_id}", response_class=HTMLResponse)
def dashboard_campaign(campaign_id: str) -> HTMLResponse:
    """One campaign's candidate comparison and release state."""
    return HTMLResponse(
        "<!doctype html><html><head><title>EvoRuntime campaign</title>"
        f"{_PAGE_STYLE}</head><body>{_campaign_detail_body(campaign_id)}</body></html>"
    )


def install_dashboard(app: FastAPI) -> None:
    """Mount the read-only dashboard routes on the application."""
    app.include_router(router)
