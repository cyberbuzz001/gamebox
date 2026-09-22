"""Report generation: JSON, CSV, Markdown, HTML and an interactive dashboard.

Reports are built from the database (endpoints + findings) plus derived
game-assessment and attack-chain data. All evidence stored in the database is
already redacted by the HTTP client, so reports never contain secrets or PII.
"""
from __future__ import annotations

import csv
import html
import io
import json
import time
import re
from pathlib import Path

from ..core.config import Config
from ..core.database import Database
from ..core.models import Finding, Severity, severity_rank
from ..games.discovery import GameDiscovery
from . import attack_chains

# Module -> report section label, for the professional PT structure.
_MODULE_SECTIONS = [
    ("Authentication Assessment", ["authentication"]),
    ("Authorization Assessment", ["authorization"]),
    ("Wallet Assessment", ["wallet", "replay", "race"]),
    ("Game-Integrity Assessment", ["games", "randomness", "game_discovery", "client_trust"]),
    ("Payment Assessment", ["payments"]),
    ("API Assessment", ["api"]),
    ("Admin Assessment", ["admin", "admin_access"]),
]


def _security_score(findings: list[Finding]) -> int:
    weights = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 8,
               Severity.LOW: 3, Severity.INFO: 0}
    return max(0, 100 - sum(weights[f.severity] for f in findings))


def _spa_fallback(f: Finding) -> bool:
    """Identify conservative SPA shell responses for admin-path findings.

    A 200 HTML shell is not evidence that an admin route is accessible. Only
    findings with admin-like endpoints and strong SPA markers are filtered.
    """
    endpoint = (f.endpoint or "").lower()
    if "admin" not in endpoint and "administrator" not in endpoint:
        return False
    markers = ("<!doctype html", "<div id=\"root\"", "<div id=\"app\"",
               "<script type=\"module\"")
    for evidence in f.evidence:
        content_type = " ".join(f"{k}:{v}" for k, v in evidence.response_headers.items()).lower()
        excerpt = (evidence.response_excerpt or "").lower()
        if evidence.status_code == 200 and "text/html" in content_type and any(m in excerpt for m in markers):
            return True
    return False


def effective_findings(db: Database) -> list[Finding]:
    """Return deduplicated findings with strong SPA-shell false positives removed."""
    result: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for finding in db.findings():
        if _spa_fallback(finding):
            continue
        key = (re.sub(r"\s+", " ", finding.title.strip().lower()),
               finding.module, finding.endpoint, finding.parameter)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def build_summary(config: Config, db: Database) -> dict:
    findings = effective_findings(db)
    return {
        "target": config.target.name or "(unnamed)",
        "environment": config.target.environment,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "security_score": _security_score(findings),
        **db.stats(),
    }


def game_assessment(db: Database) -> list[dict]:
    return [p.to_dict() for p in GameDiscovery().analyze(db.endpoints())]


def chains(db: Database) -> list[dict]:
    return [c.to_dict() for c in attack_chains.correlate(effective_findings(db))]


def to_json(config: Config, db: Database) -> str:
    return json.dumps({
        "summary": build_summary(config, db),
        "scope": {"domains": config.scope.domains, "api_hosts": config.scope.api_hosts,
                  "excluded_hosts": config.scope.excluded_hosts},
        "endpoints": [e.to_dict() for e in db.endpoints()],
        "games": game_assessment(db),
        "admin_assessment": db.get_artifact("admin_assessment"),
        "attack_chains": chains(db),
        "findings": [f.to_dict() for f in effective_findings(db)],
    }, indent=2)


def to_csv(db: Database) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "severity", "confidence", "category", "title", "endpoint",
                "cwe", "owasp", "module"])
    for f in effective_findings(db):
        w.writerow([f.id, f.severity.value, f.confidence.value, f.category.value,
                    f.title, f.endpoint, f.cwe, f.owasp, f.module])
    return buf.getvalue()


def _finding_md(f: Finding) -> list[str]:
    a = [f"#### [{f.severity.value}/{f.confidence.value}] {f.title}",
         f"- **Category:** {f.category.value} | **Module:** {f.module}",
         f"- **Endpoint:** `{f.endpoint}`" + (f" (param `{f.parameter}`)" if f.parameter else ""),
         f"- **CWE:** {f.cwe} | **OWASP:** {f.owasp}",
         f"\n{f.description}\n",
         f"**Impact:** {f.impact}\n",
         f"**Reproduction:**\n\n```\n{f.reproduction}\n```\n",
         f"**Remediation:** {f.remediation}\n"]
    if f.evidence:
        a.append("**Evidence (redacted):**\n")
        for e in f.evidence:
            line = f"- `{e.method} {e.endpoint}` -> HTTP {e.status_code}"
            if e.state_before or e.state_after:
                line += f"; state: {e.state_before} => {e.state_after}"
            if e.test_account:
                line += f"; account: {e.test_account}"
            a.append(line)
        a.append("")
    return a


def _admin_section_md(db: Database) -> list[str]:
    a = db.get_artifact("admin_assessment")
    if not a:
        return []
    out = ["# ADMINISTRATIVE ACCESS SECURITY ASSESSMENT\n",
           "## Admin Access Simulation\n", "```",
           "ADMIN ACCESS SIMULATION", "",
           f"Initial Account:\n{a['initial_account']}", "",
           f"Administrative Surface:\n{a['surface_count']} endpoints discovered", "",
           f"Accessible Without Admin:\n{a['accessible_without_admin']}", "",
           f"Potential Authorization Weaknesses:\n{a['potential_weaknesses']}", "",
           f"Confirmed Privilege Boundary Failure:\n{a['confirmed_boundary_failures']}", "",
           f"Administrative Data Modified:\n{a['admin_data_modified']}", "",
           f"Production Financial Operations:\n{a['production_financial_operations']}", "",
           f"Persistence Created:\n{a['persistence_created']}", "```\n"]

    out.append("## Discovered Administrative Surface\n")
    for ep in a["endpoints"]:
        out.append(f"- `{ep['method']} {ep['url']}` — {ep['function']} "
                   f"(via {ep['discovered_via']})")
    out.append("")

    out.append("## Authorization Matrix\n")
    out.append("| Function | Endpoint | Anonymous | Normal User | Admin |")
    out.append("|---|---|---|---|---|")
    for r in a["matrix"]:
        out.append(f"| {r['function']} | `{r['endpoint']}` | {r['anon']} | "
                   f"{r['user']} | {r['admin']} |")
    out.append("")

    out.append("## Session Security Notes\n")
    for n in a.get("session_notes", []):
        out.append(f"- {n}")
    out.append("")

    out.append("## Safety Controls Verification\n")
    out.append("Destructive administrative operations were attempted and blocked:")
    for c in a.get("safety_checks", []):
        status = "BLOCKED" if c.get("blocked") else "NOT BLOCKED"
        out.append(f"- `{c['operation']}` — {status} at {c['layer']} layer")
    out.append("")
    return out


def to_markdown(config: Config, db: Database) -> str:
    summary = build_summary(config, db)
    findings = effective_findings(db)
    endpoints = db.endpoints()
    lines: list[str] = []
    a = lines.append

    a("# GAMEBOX Security Assessment Report\n")
    a(f"**Target:** {summary['target']} | **Environment:** {summary['environment']} | "
      f"**Generated:** {summary['generated_at']} | **Score:** {summary['security_score']}/100\n")

    sev = summary["findings_by_severity"]
    a("## Executive Summary\n")
    a(f"{summary['findings']} findings across {summary['endpoints']} endpoints: "
      f"{sev['CRITICAL']} critical, {sev['HIGH']} high, {sev['MEDIUM']} medium, "
      f"{sev['LOW']} low, {sev['INFO']} info.\n")

    a("## Scope & Environment\n")
    a(f"- Domains: {', '.join(config.scope.domains) or '(none)'}")
    a(f"- API hosts: {', '.join(config.scope.api_hosts) or '(none)'}")
    a(f"- Excluded: {', '.join(config.scope.excluded_hosts) or '(none)'}")
    a(f"- Environment: {config.target.environment}\n")

    a("## Attack Surface / Application Map\n")
    by_cat: dict[str, list] = {}
    for ep in endpoints:
        by_cat.setdefault(ep.category.value, []).append(ep)
    for cat, eps in sorted(by_cat.items()):
        a(f"**{cat}** ({len(eps)})")
        for ep in eps:
            a(f"- `{ep.method} {ep.url}`")
        a("")

    a("## Game Assessment\n")
    games = game_assessment(db)
    if not games:
        a("_No game components identified in the discovered surface._\n")
    for g in games:
        a(f"### {g['name']}")
        a(f"- Action endpoints: {g['action_endpoints'] or '(none)'}")
        a(f"- Settlement endpoints: {g['settlement_endpoints'] or '(none)'}")
        a(f"- Client fields: {g['client_fields'] or '(none)'}")
        a(f"- Risk indicators: {g['risk_indicators'] or '(none)'}\n")

    # Per-domain assessment sections.
    by_module: dict[str, list[Finding]] = {}
    for f in findings:
        by_module.setdefault(f.module, []).append(f)
    for section, mods in _MODULE_SECTIONS:
        section_findings = [f for m in mods for f in by_module.get(m, [])]
        a(f"## {section}\n")
        if not section_findings:
            a("_No findings._\n")
        for f in sorted(section_findings, key=lambda x: severity_rank(x.severity)):
            lines.extend(_finding_md(f))

    lines.extend(_admin_section_md(db))

    a("## Attack Chains\n")
    ch = chains(db)
    if not ch:
        a("_No multi-step chains correlated._\n")
    for c in ch:
        a(f"### {c['name']}")
        a(f"- **Initial weakness:** {c['initial_weakness']}")
        a(f"- **Required privileges:** {c['required_privileges']}")
        a(f"- **Boundary crossed:** {c['boundary_crossed']}")
        a("- **Steps:**")
        for i, s in enumerate(c["steps"], 1):
            a(f"  {i}. {s}")
        a(f"- **Result:** {c['result']}")
        a(f"- **Business impact:** {c['business_impact']}")
        a(f"- **Remediation:** {c['remediation']}\n")

    a("## Remediation Plan\n")
    for f in sorted(findings, key=lambda x: severity_rank(x.severity)):
        a(f"- **[{f.severity.value}]** {f.title}: {f.remediation}")
    a("")

    a("## Regression Test Plan\n")
    for f in findings:
        a(f"- Re-run the `{f.module}` check on `{f.endpoint}`; the finding "
          f"'{f.title}' must no longer reproduce.")
    a("")
    return "\n".join(lines)


def to_html(config: Config, db: Database) -> str:
    """Static summary HTML (kept simple). The interactive view is dashboard.html."""
    summary = build_summary(config, db)
    findings = effective_findings(db)
    sev = summary["findings_by_severity"]
    colors = {"CRITICAL": "#b00020", "HIGH": "#d9534f", "MEDIUM": "#e0a800",
              "LOW": "#5bc0de", "INFO": "#777"}

    def esc(s):
        return html.escape(str(s))

    rows = "".join(
        f"<tr><td><span class='badge' style='background:{colors[f.severity.value]}'>"
        f"{f.severity.value}</span></td><td>{esc(f.confidence.value)}</td>"
        f"<td>{esc(f.category.value)}</td><td>{esc(f.title)}</td>"
        f"<td><code>{esc(f.endpoint)}</code></td><td>{esc(f.cwe)}</td></tr>"
        for f in findings)
    cards = "".join(
        f"<div class='card'><div class='num'>{v}</div><div class='lbl'>{k}</div></div>"
        for k, v in [("Score", f"{summary['security_score']}/100"),
                     ("Endpoints", summary["endpoints"]),
                     ("Critical", sev["CRITICAL"]), ("High", sev["HIGH"]),
                     ("Medium", sev["MEDIUM"]), ("Low", sev["LOW"])])
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>GAMEBOX Report - {esc(summary['target'])}</title>
<style>
 body{{font-family:system-ui,Arial,sans-serif;margin:24px;color:#1a1a1a;background:#fafafa}}
 .cards{{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}}
 .card{{background:#fff;border:1px solid #e2e2e2;border-radius:10px;padding:14px 18px}}
 .num{{font-size:24px;font-weight:700}} .lbl{{color:#666;font-size:12px;text-transform:uppercase}}
 table{{border-collapse:collapse;width:100%;background:#fff}}
 th,td{{border:1px solid #e2e2e2;padding:8px;text-align:left;font-size:14px}}
 th{{background:#f0f0f0}} code{{background:#f3f3f3;padding:1px 5px;border-radius:4px}}
 .badge{{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:700}}
</style></head><body>
<h1>GAMEBOX Security Assessment</h1>
<div>{esc(summary['target'])} &middot; {esc(summary['environment'])} &middot; {esc(summary['generated_at'])}</div>
<div class="cards">{cards}</div>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Confidence</th><th>Category</th>
<th>Title</th><th>Endpoint</th><th>CWE</th></tr></thead><tbody>
{rows or '<tr><td colspan=6>No findings</td></tr>'}</tbody></table>
<p style="color:#666">Evidence is redacted. Assessment performed under explicit authorization.</p>
</body></html>"""


def to_dashboard(config: Config, db: Database) -> str:
    """Interactive dashboard with client-side filters (severity/module/
    category/confidence). Data is embedded so it works from file://."""
    data = json.dumps({
        "summary": build_summary(config, db),
        "findings": [f.to_dict() for f in effective_findings(db)],
        "chains": chains(db),
        "admin": db.get_artifact("admin_assessment"),
    })
    return """<!doctype html><html><head><meta charset="utf-8">
<title>GAMEBOX Dashboard</title>
<style>
 body{font-family:system-ui,Arial,sans-serif;margin:20px;background:#0f1220;color:#e8e8f0}
 h1{margin:0 0 4px} .sub{color:#9aa}
 .cards{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}
 .card{background:#1a1f36;border:1px solid #2a3050;border-radius:10px;padding:12px 16px;min-width:90px}
 .num{font-size:22px;font-weight:800} .lbl{color:#9aa;font-size:11px;text-transform:uppercase}
 select,input{background:#1a1f36;color:#e8e8f0;border:1px solid #2a3050;border-radius:6px;padding:6px}
 table{border-collapse:collapse;width:100%;margin-top:12px}
 th,td{border-bottom:1px solid #2a3050;padding:8px;text-align:left;font-size:13px;vertical-align:top}
 th{color:#9aa;text-transform:uppercase;font-size:11px}
 code{background:#11152a;padding:1px 5px;border-radius:4px}
 .badge{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:800}
 details summary{cursor:pointer}
 .filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
</style></head><body>
<h1>GAMEBOX Dashboard</h1><div class="sub" id="sub"></div>
<div class="cards" id="cards"></div>
<div class="filters">
 <input id="q" placeholder="search title/endpoint..." oninput="render()">
 <select id="sev" onchange="render()"><option value="">severity: all</option></select>
 <select id="mod" onchange="render()"><option value="">module: all</option></select>
 <select id="cat" onchange="render()"><option value="">category: all</option></select>
 <select id="conf" onchange="render()"><option value="">confidence: all</option></select>
</div>
<table><thead><tr><th>Sev</th><th>Conf</th><th>Module</th><th>Category</th>
<th>Title</th><th>Endpoint</th></tr></thead><tbody id="rows"></tbody></table>
<h2>Attack Chains</h2><div id="chains"></div>
<h2>Administrative Access</h2><div id="admin"></div>
<script>
const DATA = __DATA__;
const COLORS={CRITICAL:'#b00020',HIGH:'#d9534f',MEDIUM:'#e0a800',LOW:'#5bc0de',INFO:'#777'};
function uniq(a){return [...new Set(a)].sort();}
function fill(id,vals,label){const s=document.getElementById(id);
 uniq(vals).forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=label+': '+v;s.appendChild(o);});}
function init(){
 const s=DATA.summary; document.getElementById('sub').textContent=
  s.target+' \\u00b7 '+s.environment+' \\u00b7 '+s.generated_at;
 const sev=s.findings_by_severity||{};
 const cards=[['Score',s.security_score+'/100'],['Endpoints',s.endpoints],
  ['Critical',sev.CRITICAL||0],['High',sev.HIGH||0],['Medium',sev.MEDIUM||0],
  ['Low',sev.LOW||0],['Info',sev.INFO||0]];
 document.getElementById('cards').innerHTML=cards.map(c=>
  '<div class=card><div class=num>'+c[1]+'</div><div class=lbl>'+c[0]+'</div></div>').join('');
 fill('sev',DATA.findings.map(f=>f.severity),'severity');
 fill('mod',DATA.findings.map(f=>f.module),'module');
 fill('cat',DATA.findings.map(f=>f.category),'category');
 fill('conf',DATA.findings.map(f=>f.confidence),'confidence');
 document.getElementById('chains').innerHTML = (DATA.chains||[]).map(c=>
  '<details><summary><b>'+c.name+'</b> \\u2014 '+c.result+'</summary><ol>'+
  c.steps.map(x=>'<li>'+x+'</li>').join('')+'</ol><p>Impact: '+c.business_impact+
  '<br>Remediation: '+c.remediation+'</p></details>').join('') || '<i>none</i>';
 renderAdmin();
 render();
}
function renderAdmin(){
 const a=DATA.admin; const el=document.getElementById('admin');
 if(!a){el.innerHTML='<i>admin_access module not run</i>';return;}
 const cards=[['Surface',a.surface_count],['Accessible w/o admin',a.accessible_without_admin],
  ['Potential',a.potential_weaknesses],['Confirmed boundary failures',a.confirmed_boundary_failures],
  ['Data modified',a.admin_data_modified],['Persistence',a.persistence_created]];
 let html='<div class=cards>'+cards.map(c=>
  '<div class=card><div class=num>'+c[1]+'</div><div class=lbl>'+c[0]+'</div></div>').join('')+'</div>';
 html+='<table><thead><tr><th>Function</th><th>Endpoint</th><th>Anon</th><th>User</th>'+
  '<th>Admin</th></tr></thead><tbody>'+(a.matrix||[]).map(r=>{
   const col=v=>v==='ACCESS_ALLOWED'?'#b00020':(v==='NOT_TESTED'?'#777':'#2a7');
   return '<tr><td>'+r.function+'</td><td><code>'+r.endpoint+'</code></td>'+
    ['anon','user','admin'].map(k=>'<td style="color:'+col(r[k])+'">'+r[k]+'</td>').join('')+
    '</tr>';}).join('')+'</tbody></table>';
 html+='<p>Safety verification: '+(a.safety_checks||[]).map(c=>
  c.operation+' = '+(c.blocked?'BLOCKED':'NOT BLOCKED')+' ('+c.layer+')').join('; ')+'</p>';
 el.innerHTML=html;
}
function render(){
 const q=document.getElementById('q').value.toLowerCase();
 const sev=document.getElementById('sev').value, mod=document.getElementById('mod').value;
 const cat=document.getElementById('cat').value, conf=document.getElementById('conf').value;
 const rows=DATA.findings.filter(f=>
  (!sev||f.severity===sev)&&(!mod||f.module===mod)&&(!cat||f.category===cat)&&
  (!conf||f.confidence===conf)&&
  (!q||(f.title+' '+f.endpoint).toLowerCase().includes(q)))
 .sort((a,b)=>({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[a.severity]-
              {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[b.severity]));
 document.getElementById('rows').innerHTML=rows.map(f=>
  '<tr><td><span class=badge style="background:'+COLORS[f.severity]+'">'+f.severity+
  '</span></td><td>'+f.confidence+'</td><td>'+f.module+'</td><td>'+f.category+
  '</td><td><b>'+f.title+'</b><br><small>'+(f.remediation||'')+'</small></td><td><code>'+
  f.endpoint+'</code></td></tr>').join('') ||
  '<tr><td colspan=6><i>no matching findings</i></td></tr>';
}
init();
</script></body></html>""".replace("__DATA__", data)


def write_all(config: Config, db: Database, out_dir) -> dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "json": (out / "report.json", to_json(config, db)),
        "csv": (out / "findings.csv", to_csv(db)),
        "markdown": (out / "report.md", to_markdown(config, db)),
        "html": (out / "report.html", to_html(config, db)),
        "dashboard": (out / "dashboard.html", to_dashboard(config, db)),
    }
    for _, (path, content) in files.items():
        path.write_text(content, encoding="utf-8")
    return {k: str(v[0]) for k, v in files.items()}
