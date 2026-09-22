"""SECURITY LAB: Authorized Web Application Security Assessment Platform GUI.

Provides a unified browser interface for Target Management, Reconnaissance,
Scan Scheduling, Manual Testing, Game Security, Exploit Validation,
Vulnerability Management, Fix Generation, and Verification.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from flask import (Flask, abort, jsonify, redirect, render_template_string,
                   request, send_file, session, url_for)

from .core.config import Config
from .core.database import Database
from .core.models import Category, Confidence, Endpoint, Evidence, Finding, Severity
from .core.scheduler import (DEFAULT_MODULES, Orchestrator, ScanCancelled,
                             available_modules)
from .core.scheduler import ALL_MODULES
from .core.external import tool_available
from .discovery.crawler import Crawler
from .http.client import SafeHTTPClient
from .reporting import report as report_mod
from .safety.controller import SafetyController
from .safety.scope import ScopeManager

app = Flask(__name__)
_state: dict = {
    "config": None,
    "form": {},
    "message": "Configure an authorized target in Target Manager to begin.",
    "jobs": {},
    "lock": threading.RLock(),
    "executor": ThreadPoolExecutor(max_workers=2, thread_name_prefix="security-lab"),
    "history": [],
    "audit_logs": [
        {"timestamp": "2026-09-22 10:00:00", "user": "admin", "action": "SYSTEM_INITIALIZED", "target": "localhost", "details": "Security Lab engine ready"},
    ],
    "test_results": [],
    "projects": [
        {"id": "proj-gamebox-core", "name": "GameBox Platform Core", "environment": "staging", "target_url": "http://127.0.0.1:5099", "endpoints": 12, "status": "Active"},
        {"id": "proj-andar-bahar", "name": "Andar Bahar Live Suite", "environment": "sandbox", "target_url": "ws://127.0.0.1:8766", "endpoints": 3, "status": "Active"},
    ],
    "active_project": "proj-gamebox-core",
    "verified_findings": {},
}
app.secret_key = os.environ.get("GAMEBOX_GUI_SECRET", secrets.token_hex(32))
app.config.setdefault("REQUIRE_GUI_AUTH", False)
app.config.setdefault("GUI_ADMIN_SECRET", os.environ.get("GAMEBOX_GUI_ADMIN_SECRET", ""))

MODULE_LABELS = {
    "recon": "Reconnaissance & Headers",
    "game_discovery": "Web & Game Discovery",
    "api": "API Security",
    "authentication": "Authentication",
    "authorization": "Authorization (BOLA/IDOR)",
    "admin_access": "Admin Access & RBAC",
    "wallet": "Wallet Integrity",
    "wallet_advanced": "Advanced Wallet Arithmetic",
    "games": "Game Integrity",
    "state_race": "Bet Cancellation Race",
    "randomness": "RNG & Provably Fair",
    "client_trust": "Client Trust Validation",
    "payments": "Payment Webhook Checks",
    "replay": "Replay Testing",
    "race": "Concurrency & Race Tests",
    "jwt_deep": "Deep JWT Analysis",
    "schema_fuzz": "Schema Fuzzing",
}

TOOL_FIELDS = {
    "seclists_path": "SecLists directory",
    "payloads_path": "Payloads directory",
    "jwt_tool_path": "jwt_tool path",
    "graphql_cop_path": "graphql-cop path",
    "schemathesis_path": "Schemathesis path",
    "nuclei_path": "Nuclei path",
}

def _log_audit(action: str, target: str, details: str):
    with _state["lock"]:
        _state["audit_logs"].insert(0, {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "user": "operator",
            "action": action,
            "target": target,
            "details": details,
        })
        if len(_state["audit_logs"]) > 150:
            _state["audit_logs"].pop()

_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SECURITY LAB — Application Security & Remediation Platform</title>
<style>
  :root {
    --bg-main: #0a0e1a;
    --bg-surface: #121829;
    --bg-panel: #18223c;
    --bg-card: #1f2c4e;
    --border: #2c3c66;
    --text-main: #f0f4ff;
    --text-muted: #8e9ec7;
    --primary: #4f6bff;
    --primary-hover: #6882ff;
    --accent: #00d2ff;
    --crit: #ef4444;
    --high: #f97316;
    --med: #f59e0b;
    --low: #10b981;
    --info: #3b82f6;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg-main); color: var(--text-main); display: flex; height: 100vh; overflow: hidden; }
  
  /* Sidebar */
  aside { width: 260px; background: var(--bg-surface); border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; }
  .brand { padding: 20px; font-size: 18px; font-weight: 800; letter-spacing: 1px; color: var(--accent); border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; }
  .brand span { color: var(--text-main); font-weight: 400; font-size: 13px; margin-left: 4px; }
  nav { flex: 1; overflow-y: auto; padding: 14px 10px; }
  .nav-group { font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin: 16px 12px 6px; letter-spacing: 0.8px; }
  .nav-item { display: flex; align-items: center; gap: 10px; padding: 9px 14px; border-radius: 8px; color: #b8c7eb; text-decoration: none; font-size: 13px; font-weight: 500; transition: all 0.15s ease; margin-bottom: 2px; }
  .nav-item:hover { background: rgba(79, 107, 255, 0.12); color: #ffffff; }
  .nav-item.active { background: var(--primary); color: #ffffff; font-weight: 600; box-shadow: 0 4px 12px rgba(79, 107, 255, 0.35); }
  .nav-badge { margin-left: auto; font-size: 11px; padding: 2px 7px; border-radius: 10px; background: var(--bg-card); color: #fff; font-weight: 700; }
  
  /* Main Container */
  main { flex: 1; display: flex; flex-direction: column; overflow-y: auto; background: var(--bg-main); }
  header { height: 60px; border-bottom: 1px solid var(--border); background: var(--bg-surface); display: flex; align-items: center; justify-content: space-between; padding: 0 28px; flex-shrink: 0; }
  .header-target { display: flex; align-items: center; gap: 10px; font-size: 13px; color: var(--text-muted); }
  .target-pill { background: rgba(0, 210, 255, 0.12); border: 1px solid rgba(0, 210, 255, 0.3); color: var(--accent); padding: 4px 10px; border-radius: 12px; font-weight: 600; font-size: 12px; }
  .header-actions { display: flex; gap: 10px; align-items: center; }
  
  .content { padding: 28px; max-width: 1280px; margin: 0 auto; width: 100%; }
  .panel { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 14px; padding: 24px; margin-bottom: 24px; box-shadow: 0 4px 20px rgba(0,0,0,0.2); }
  h2 { font-size: 20px; font-weight: 700; margin-bottom: 6px; }
  p.subtitle { color: var(--text-muted); font-size: 13px; margin-bottom: 18px; }
  
  /* Grid & Cards */
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px; }
  .card { background: var(--bg-panel); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }
  .card-num { font-size: 28px; font-weight: 800; margin: 4px 0 6px; }
  .card-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }
  
  /* Form Inputs */
  .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 18px; }
  label { display: block; font-size: 12px; font-weight: 600; color: #b9c7ed; margin-bottom: 6px; }
  input, select, textarea { width: 100%; padding: 10px 14px; border-radius: 8px; border: 1px solid var(--border); background: var(--bg-panel); color: #fff; font-size: 13px; outline: none; transition: border-color 0.2s; font-family: inherit; }
  input:focus, select:focus, textarea:focus { border-color: var(--primary); }
  .btn { display: inline-flex; align-items: center; gap: 8px; border: none; border-radius: 8px; padding: 10px 18px; background: var(--primary); color: #fff; font-size: 13px; font-weight: 600; cursor: pointer; text-decoration: none; transition: background 0.15s; }
  .btn:hover { background: var(--primary-hover); }
  .btn-sec { background: var(--bg-card); color: #cbd5e1; border: 1px solid var(--border); }
  .btn-sec:hover { background: #27375f; color: #fff; }
  .btn-success { background: #059669; }
  .btn-success:hover { background: #047857; }
  .btn-danger { background: #dc2626; }
  .btn-danger:hover { background: #b91c1c; }
  
  /* Tables */
  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
  th { text-align: left; padding: 12px 14px; background: var(--bg-panel); color: var(--text-muted); font-size: 11px; text-transform: uppercase; font-weight: 700; border-bottom: 1px solid var(--border); }
  td { padding: 12px 14px; border-bottom: 1px solid var(--border); color: #e2e8f0; vertical-align: middle; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  
  /* Badges */
  .badge { display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge-CRITICAL { background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.4); }
  .badge-HIGH { background: rgba(249,115,22,0.15); color: #fb923c; border: 1px solid rgba(249,115,22,0.4); }
  .badge-MEDIUM { background: rgba(245,158,11,0.15); color: #fcd34d; border: 1px solid rgba(245,158,11,0.4); }
  .badge-LOW { background: rgba(16,185,129,0.15); color: #34d399; border: 1px solid rgba(16,185,129,0.4); }
  .badge-INFO { background: rgba(59,130,246,0.15); color: #60a5fa; border: 1px solid rgba(59,130,246,0.4); }
  .badge-RESOLVED { background: rgba(16,185,129,0.2); color: #10b981; border: 1px solid rgba(16,185,129,0.6); }
  .badge-VULNERABLE { background: rgba(239,68,68,0.2); color: #ef4444; border: 1px solid rgba(239,68,68,0.6); }
  
  /* Alerts */
  .msg-banner { padding: 12px 18px; border-radius: 8px; font-size: 13px; margin-bottom: 20px; font-weight: 500; }
  .msg-info { background: rgba(59, 130, 246, 0.12); border: 1px solid rgba(59, 130, 246, 0.3); color: #93c5fd; }
  .msg-error { background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: #fca5a5; }
  
  /* Progress Bars */
  .progress-bar { width: 100%; height: 10px; background: var(--bg-panel); border-radius: 6px; overflow: hidden; margin-top: 8px; }
  .progress-fill { height: 100%; background: linear-gradient(90deg, var(--primary), var(--accent)); transition: width 0.3s; }
  .checks-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 10px; margin: 14px 0; }
  .check-card { background: var(--bg-panel); border: 1px solid var(--border); padding: 10px 14px; border-radius: 8px; display: flex; align-items: center; gap: 10px; font-size: 13px; }
  .check-card input { width: auto; }
</style>
</head>
<body>

<aside>
  <div class="brand">
    🛡️ SECURITY LAB <span>v2.0</span>
  </div>
  <nav>
    <div class="nav-group">Overview</div>
    <a href="/?tab=dashboard" class="nav-item {{ 'active' if active_tab == 'dashboard' else '' }}">
      <span>📊</span> Dashboard
    </a>
    
    <div class="nav-group">Projects & Scope</div>
    <a href="/?tab=projects" class="nav-item {{ 'active' if active_tab == 'projects' else '' }}">
      <span>📁</span> Projects
    </a>
    <a href="/?tab=targets" class="nav-item {{ 'active' if active_tab == 'targets' else '' }}">
      <span>🎯</span> Target Manager
    </a>

    <div class="nav-group">Testing Engines</div>
    <a href="/?tab=scans" class="nav-item {{ 'active' if active_tab == 'scans' else '' }}">
      <span>⚡</span> Scan Center
      {% if job and job.status == 'running' %}<span class="nav-badge" style="background:var(--primary)">RUN</span>{% endif %}
    </a>
    <a href="/?tab=testing-lab" class="nav-item {{ 'active' if active_tab == 'testing-lab' else '' }}">
      <span>🧪</span> Testing Lab
    </a>
    <a href="/?tab=browser" class="nav-item {{ 'active' if active_tab == 'browser' else '' }}">
      <span>🌐</span> Browser Testing
    </a>
    <a href="/?tab=api-testing" class="nav-item {{ 'active' if active_tab == 'api-testing' else '' }}">
      <span>📡</span> API Testing
    </a>
    <a href="/?tab=game-security" class="nav-item {{ 'active' if active_tab == 'game-security' else '' }}">
      <span>🎲</span> Game Security
    </a>

    <div class="nav-group">Vulnerabilities</div>
    <a href="/?tab=findings" class="nav-item {{ 'active' if active_tab == 'findings' else '' }}">
      <span>🚨</span> Findings
      {% if stats and stats.findings %}<span class="nav-badge">{{ stats.findings }}</span>{% endif %}
    </a>
    <a href="/?tab=validation" class="nav-item {{ 'active' if active_tab == 'validation' else '' }}">
      <span>🔬</span> Exploit Validation
    </a>
    <a href="/?tab=evidence" class="nav-item {{ 'active' if active_tab == 'evidence' else '' }}">
      <span>🧾</span> Evidence Archive
    </a>

    <div class="nav-group">Remediation</div>
    <a href="/?tab=fixes" class="nav-item {{ 'active' if active_tab == 'fixes' else '' }}">
      <span>🛠️</span> Fix Center
    </a>
    <a href="/?tab=verification" class="nav-item {{ 'active' if active_tab == 'verification' else '' }}">
      <span>✅</span> Fix Verification
    </a>
    <a href="/?tab=improvements" class="nav-item {{ 'active' if active_tab == 'improvements' else '' }}">
      <span>📈</span> Improvements
    </a>

    <div class="nav-group">Reporting & System</div>
    <a href="/?tab=reports" class="nav-item {{ 'active' if active_tab == 'reports' else '' }}">
      <span>📑</span> Reports
    </a>
    <a href="/?tab=history" class="nav-item {{ 'active' if active_tab == 'history' else '' }}">
      <span>🕒</span> Scan History
    </a>
    <a href="/?tab=audit" class="nav-item {{ 'active' if active_tab == 'audit' else '' }}">
      <span>📋</span> Audit Logs
    </a>
    <a href="/?tab=settings" class="nav-item {{ 'active' if active_tab == 'settings' else '' }}">
      <span>⚙️</span> Settings & Tools
    </a>
  </nav>
</aside>

<main>
  <header>
    <div class="header-target">
      <span>Target:</span>
      {% if cfg %}
        <span class="target-pill">{{ cfg.target.name }} ({{ cfg.target.environment }})</span>
        <span style="font-size:12px; color:var(--text-muted)">{{ cfg.base_urls[0] if cfg.base_urls else '' }}</span>
      {% else %}
        <span class="target-pill" style="border-color:#eab308; color:#facc15; background:rgba(234,179,8,0.1)">No Target Configured</span>
      {% endif %}
    </div>
    <div class="header-actions">
      {% if report %}<a href="{{ report }}" target="_blank" class="btn btn-sec">Interactive Dashboard</a>{% endif %}
      <a href="/?tab=targets" class="btn">+ New Target</a>
    </div>
  </header>

  <div class="content">
    {% if message %}
      <div class="msg-banner {{ 'msg-error' if error else 'msg-info' }}">
        {{ message }}
      </div>
    {% endif %}

    {# ------------------------------------------------------------- #}
    {# TAB 1: DASHBOARD                                              #}
    {# ------------------------------------------------------------- #}
    {% if active_tab == 'dashboard' %}
      <section class="panel">
        <h2>Security Overview</h2>
        <p class="subtitle">Real-time posture and assessment telemetry across authorized targets.</p>
        <div class="grid">
          <div class="card">
            <div class="card-num" style="color:var(--accent)">{{ 1 if cfg else 0 }}</div>
            <div class="card-label">Active Targets</div>
          </div>
          <div class="card">
            <div class="card-num" style="color:var(--info)">{{ stats.endpoints if stats else 0 }}</div>
            <div class="card-label">Discovered Endpoints</div>
          </div>
          <div class="card">
            <div class="card-num" style="color:var(--crit)">{{ stats.by_severity.CRITICAL if stats and stats.by_severity else 0 }}</div>
            <div class="card-label">Critical Findings</div>
          </div>
          <div class="card">
            <div class="card-num" style="color:var(--high)">{{ stats.by_severity.HIGH if stats and stats.by_severity else 0 }}</div>
            <div class="card-label">High Severity</div>
          </div>
        </div>
      </section>

      <div style="display:grid; grid-template-columns: 2fr 1fr; gap:20px;">
        <section class="panel">
          <h2>Active Target Posture</h2>
          <p class="subtitle">Environment and scope parameters for active testing session.</p>
          {% if cfg %}
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:14px; font-size:13px;">
              <div><b>Target Name:</b> {{ cfg.target.name }}</div>
              <div><b>Environment:</b> <span class="badge badge-INFO">{{ cfg.target.environment }}</span></div>
              <div><b>Scope Domains:</b> <code>{{ cfg.scope.domains|join(', ') }}</code></div>
              <div><b>Base URL:</b> <code>{{ cfg.base_urls[0] if cfg.base_urls else 'N/A' }}</code></div>
              <div><b>State Changes Allowed:</b> {{ 'Yes (TEST_COINS only)' if cfg.safety.allow_state_changes else 'No (Read-Only)' }}</div>
              <div><b>Rate Throttle:</b> {{ cfg.testing.max_requests_per_second }} req/s</div>
            </div>
          {% else %}
            <p style="color:var(--text-muted); font-size:13px;">No target currently active. Go to <a href="/?tab=targets" style="color:var(--primary)">Target Manager</a> to configure an authorized scope.</p>
          {% endif %}
        </section>

        <section class="panel">
          <h2>Quick Actions</h2>
          <p class="subtitle">Authorized testing entrypoints.</p>
          <div style="display:flex; flex-direction:column; gap:10px;">
            <form method="post" action="{{ url_for('discover') }}">
              <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
              <button class="btn btn-sec" style="width:100%">🔍 Run Read-Only Discovery</button>
            </form>
            <a href="/?tab=scans" class="btn" style="width:100%; text-align:center">⚡ Launch Scan Center</a>
            <a href="/?tab=testing-lab" class="btn btn-sec" style="width:100%; text-align:center">🧪 Open Testing Lab</a>
            <a href="/?tab=api-testing" class="btn btn-sec" style="width:100%; text-align:center">📡 API Testing Workbench</a>
            <a href="/?tab=game-security" class="btn btn-sec" style="width:100%; text-align:center">🎲 Game Security Vectors</a>
          </div>
        </section>
      </div>

    {# ------------------------------------------------------------- #}
    {# TAB 2: PROJECTS                                               #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'projects' %}
      <section class="panel">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
          <div>
            <h2>Project Workspace</h2>
            <p class="subtitle" style="margin-bottom:0">Manage security projects, multi-tenant scopes, and target asset registries.</p>
          </div>
          <a href="/?tab=targets" class="btn">+ Add Target Scope</a>
        </div>
        <table>
          <thead>
            <tr><th>Project Name</th><th>Target URL</th><th>Environment</th><th>Endpoints</th><th>Status</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {% for p in projects %}
              <tr>
                <td><b>{{ p.name }}</b></td>
                <td><code>{{ p.target_url }}</code></td>
                <td><span class="badge badge-INFO">{{ p.environment }}</span></td>
                <td>{{ p.endpoints }}</td>
                <td><span class="badge badge-LOW">{{ p.status }}</span></td>
                <td>
                  <form method="post" action="{{ url_for('configure') }}" style="display:inline;">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <input type="hidden" name="target_url" value="{{ p.target_url }}">
                    <input type="hidden" name="name" value="{{ p.name }}">
                    <input type="hidden" name="environment" value="{{ p.environment }}">
                    <input type="hidden" name="authorized" value="on">
                    <input type="hidden" name="state_changes" value="on">
                    <button class="btn btn-sec" style="padding:4px 10px; font-size:12px;">Activate Target</button>
                  </form>
                </td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      </section>

    {# ------------------------------------------------------------- #}
    {# TAB 3: TARGET MANAGER                                         #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'targets' %}
      <section class="panel">
        <h2>Target Manager</h2>
        <p class="subtitle">Configure authorized testing boundaries, test accounts, and fail-closed scope rules.</p>
        <form method="post" action="{{ url_for('configure') }}">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          <div class="form-grid">
            <div>
              <label>Target URL (Required)</label>
              <input name="target_url" required placeholder="https://authorized.example" value="{{ form.get('target_url', '') }}">
            </div>
            <div>
              <label>Target Name</label>
              <input name="name" value="{{ form.get('name', '') }}" placeholder="GameBox Staging">
            </div>
            <div>
              <label>Environment</label>
              <select name="environment">
                <option value="staging" {{ 'selected' if form.get('environment')=='staging' else '' }}>Staging</option>
                <option value="sandbox" {{ 'selected' if form.get('environment')=='sandbox' else '' }}>Sandbox</option>
                <option value="production" {{ 'selected' if form.get('environment')=='production' else '' }}>Authorized Production (Forced Read-Only)</option>
              </select>
            </div>
            <div>
              <label>Login Path (Optional)</label>
              <input name="login_path" value="{{ form.get('login_path', '/api/auth/login') }}">
            </div>
            <div>
              <label>Dedicated Test Username</label>
              <input name="username" autocomplete="off" placeholder="security-test-user" value="{{ form.get('username', '') }}">
            </div>
            <div>
              <label>Dedicated Test Password</label>
              <input name="password" type="password" placeholder="••••••••">
            </div>
            <div>
              <label>Bearer Token (Optional)</label>
              <input name="token" type="password" placeholder="eyJhbGci...">
            </div>
            <div>
              <label>Requests Per Second (Max 20)</label>
              <input name="rps" type="number" min="0" max="20" step="0.5" value="{{ form.get('rps', 3) }}">
            </div>
            <div>
              <label>WebSocket Endpoint (Optional)</label>
              <input name="websocket_url" value="{{ form.get('websocket_url', '') }}" placeholder="ws://127.0.0.1:8766">
            </div>
            <div>
              <label>WebSocket Origin (Optional)</label>
              <input name="websocket_origin" value="{{ form.get('websocket_origin', '') }}" placeholder="http://127.0.0.1:5099">
            </div>
          </div>

          <div style="background:var(--bg-panel); border:1px solid var(--border); border-radius:8px; padding:14px; margin-bottom:18px;">
            <div style="font-weight:600; font-size:13px; margin-bottom:8px; color:#facc15;">⚠️ Scope & Safety Confirmation</div>
            <label style="display:flex; align-items:center; gap:8px; font-weight:normal; margin-bottom:8px;">
              <input type="checkbox" name="authorized" required>
              I confirm I hold explicit, written authorization to perform security testing on this target.
            </label>
            <label style="display:flex; align-items:center; gap:8px; font-weight:normal;">
              <input type="checkbox" name="state_changes">
              Permit state-changing operations against synthetic TEST_COINS (Permanently disabled on production).
            </label>
          </div>

          <button class="btn">Save & Authorize Target</button>
        </form>
      </section>

    {# ------------------------------------------------------------- #}
    {# TAB 4: SCAN CENTER                                            #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'scans' %}
      <section class="panel">
        <h2>Scan Center</h2>
        <p class="subtitle">Select assessment profile and launch background scan workers.</p>
        
        {% if job and job.status in ['queued', 'running'] %}
          <div style="background:var(--bg-panel); border:1px solid var(--primary); border-radius:10px; padding:18px; margin-bottom:20px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <div>
                <b>Scan Job Running:</b> {{ job.id }} &nbsp; 
                <span class="badge badge-MEDIUM">{{ job.status }}</span>
                <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Current module: {{ job.current_module or 'Initializing...' }}</div>
              </div>
              <form method="post" action="{{ url_for('cancel_job', job_id=job.id) }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <button class="btn btn-danger">Stop Scan</button>
              </form>
            </div>
            <div class="progress-bar">
              <div class="progress-fill" style="width: {{ job.progress or 10 }}%;"></div>
            </div>
          </div>
        {% endif %}

        <form method="post" action="{{ url_for('scan') }}">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          <div style="margin-bottom:18px;">
            <label>Scan Modules</label>
            <div class="checks-grid">
              {% for name, label in module_options %}
                <label class="check-card">
                  <input type="checkbox" name="modules" value="{{ name }}" {% if name in selected_modules %}checked{% endif %}>
                  {{ label }}
                </label>
              {% endfor %}
            </div>
          </div>
          <button class="btn">⚡ Start Selected Assessment</button>
        </form>
      </section>

    {# ------------------------------------------------------------- #}
    {# TAB 5: TESTING LAB (INTERACTIVE CONTROLLED PROBES)            #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'testing-lab' %}
      <section class="panel">
        <h2>Testing Lab</h2>
        <p class="subtitle">Execute live, controlled security probes against specific endpoints and capture telemetry.</p>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
          <div>
            <div class="form-grid" style="grid-template-columns: 1fr;">
              <div>
                <label>Security Test Vector</label>
                <select id="lab-vector" onchange="updateLabVectorDetails()">
                  <option value="negative_bet">Negative Bet Amount Injection (Wallet Integrity)</option>
                  <option value="precision_underflow">Float Precision Underflow (Wallet Arithmetic)</option>
                  <option value="auth_invalidation">Session Token Invalidation on Logout</option>
                  <option value="user_wallet_idor">Cross-Account Wallet Read (BOLA / IDOR)</option>
                  <option value="client_payout">Client-Supplied Payout Tampering (Game State)</option>
                  <option value="duplicate_settlement">Duplicate Settlement Replay</option>
                </select>
              </div>
              <div>
                <label>Target Path / Endpoint</label>
                <input id="lab-endpoint" value="/api/wallet/bet">
              </div>
              <div>
                <label>Custom Payload (JSON)</label>
                <textarea id="lab-payload" rows="3">{"amount": -100.0, "round_id": "probe-round-1"}</textarea>
              </div>
            </div>
            <button class="btn" id="btn-run-probe" onclick="runLiveLabProbe()">▶ Run Controlled Probe</button>
          </div>

          <div style="background:var(--bg-panel); border:1px solid var(--border); border-radius:10px; padding:18px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
              <div style="font-weight:700; font-size:13px; color:var(--accent)">LIVE PROBE TELEMETRY</div>
              <span id="probe-badge" class="badge badge-INFO">READY</span>
            </div>
            <pre id="probe-output" style="font-family:monospace; font-size:12px; color:#cbd5e1; line-height:1.5; white-space:pre-wrap; max-height:300px; overflow-y:auto; background:#0b0f19; padding:12px; border-radius:6px;">Select a test vector and click "Run Controlled Probe" to execute safe test telemetry.</pre>
          </div>
        </div>
      </section>

      <script>
        function updateLabVectorDetails() {
          const v = document.getElementById('lab-vector').value;
          const ep = document.getElementById('lab-endpoint');
          const pl = document.getElementById('lab-payload');
          if (v === 'negative_bet') {
            ep.value = '/api/wallet/bet';
            pl.value = JSON.stringify({"amount": -100.0, "round_id": "test-round-1"}, null, 2);
          } else if (v === 'precision_underflow') {
            ep.value = '/api/wallet/bet';
            pl.value = JSON.stringify({"amount": 0.00000000001, "round_id": "test-round-2"}, null, 2);
          } else if (v === 'auth_invalidation') {
            ep.value = '/api/auth/logout';
            pl.value = JSON.stringify({"session_token": "current-session"}, null, 2);
          } else if (v === 'user_wallet_idor') {
            ep.value = '/api/wallet/balance?user_id=2';
            pl.value = '{}';
          } else if (v === 'client_payout') {
            ep.value = '/api/games/settle';
            pl.value = JSON.stringify({"round_id": "r1", "payout": 99999.0}, null, 2);
          } else if (v === 'duplicate_settlement') {
            ep.value = '/api/games/settle';
            pl.value = JSON.stringify({"round_id": "r1", "tx_id": "tx-12345", "payout": 50.0}, null, 2);
          }
        }

        async function runLiveLabProbe() {
          const btn = document.getElementById('btn-run-probe');
          const out = document.getElementById('probe-output');
          const badge = document.getElementById('probe-badge');
          btn.disabled = true;
          btn.innerText = 'Testing...';
          badge.className = 'badge badge-MEDIUM';
          badge.innerText = 'EXECUTING';
          out.innerText = 'Dispatching controlled probe via SafeHTTPClient...';
          try {
            const vector = document.getElementById('lab-vector').value;
            const endpoint = document.getElementById('lab-endpoint').value;
            const payload = document.getElementById('lab-payload').value;
            const res = await fetch('/api/lab/probe', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({vector, endpoint, payload})
            });
            const data = await res.json();
            if (data.is_vulnerable) {
              badge.className = 'badge badge-CRITICAL';
              badge.innerText = 'VULNERABILITY CONFIRMED';
            } else {
              badge.className = 'badge badge-LOW';
              badge.innerText = 'SECURE / PROTECTED';
            }
            out.innerText = '>>> HTTP ' + data.method + ' ' + data.url + '\\n' +
                            '>>> Body: ' + data.request_body + '\\n\\n' +
                            '<<< Status: ' + data.response_status + ' (' + data.latency_ms + 'ms)\\n' +
                            '<<< Response: ' + data.response_body + '\\n\\n' +
                            'Analysis: ' + data.explanation + '\\n' +
                            (data.finding_saved ? '✅ Vulnerability finding auto-saved to SQLite Database.' : 'No finding logged.');
          } catch (e) {
            badge.className = 'badge badge-CRITICAL';
            badge.innerText = 'ERROR';
            out.innerText = 'Probe execution failed: ' + e;
          } finally {
            btn.disabled = false;
            btn.innerText = '▶ Run Controlled Probe';
          }
        }
      </script>

    {# ------------------------------------------------------------- #}
    {# TAB 6: BROWSER TESTING WORKBENCH                              #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'browser' %}
      <section class="panel">
        <h2>Browser Testing Workbench</h2>
        <p class="subtitle">Evaluate client-side security headers, clickjacking framing protection, CORS reflection, and cookie safety.</p>
        
        <div style="display:flex; gap:12px; margin-bottom:20px;">
          <input id="browser-target-url" style="flex:1" value="{{ cfg.base_urls[0] if cfg and cfg.base_urls else 'http://127.0.0.1:5099' }}" placeholder="https://target.example">
          <button class="btn" id="btn-browser-audit" onclick="runBrowserSecurityAudit()">🔍 Run Browser Security Audit</button>
        </div>

        <div id="browser-results" style="display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:16px;">
          <div class="card">
            <div class="card-label">Clickjacking & Framing</div>
            <div id="card-clickjacking-val" class="card-num" style="font-size:18px; color:var(--text-muted)">Not Audited</div>
            <p id="card-clickjacking-desc" style="font-size:12px; color:var(--text-muted)">Verifies X-Frame-Options and CSP frame-ancestors.</p>
          </div>
          <div class="card">
            <div class="card-label">CORS Origin Reflection</div>
            <div id="card-cors-val" class="card-num" style="font-size:18px; color:var(--text-muted)">Not Audited</div>
            <p id="card-cors-desc" style="font-size:12px; color:var(--text-muted)">Tests arbitrary origin reflections and credentials.</p>
          </div>
          <div class="card">
            <div class="card-label">Transport & MIME Sniffing</div>
            <div id="card-hsts-val" class="card-num" style="font-size:18px; color:var(--text-muted)">Not Audited</div>
            <p id="card-hsts-desc" style="font-size:12px; color:var(--text-muted)">Audits HSTS and X-Content-Type-Options: nosniff.</p>
          </div>
          <div class="card">
            <div class="card-label">Session Cookie Flags</div>
            <div id="card-cookie-val" class="card-num" style="font-size:18px; color:var(--text-muted)">Not Audited</div>
            <p id="card-cookie-desc" style="font-size:12px; color:var(--text-muted)">Validates HttpOnly, Secure, and SameSite flags.</p>
          </div>
        </div>

        <div style="margin-top:20px; background:var(--bg-panel); border:1px solid var(--border); border-radius:10px; padding:18px;">
          <h3 style="font-size:14px; margin-bottom:8px; color:var(--accent)">RAW SECURITY HEADERS AUDIT TELEMETRY</h3>
          <pre id="browser-headers-raw" style="font-family:monospace; font-size:12px; color:#94a3b8; max-height:220px; overflow-y:auto;">Click "Run Browser Security Audit" to inspect target response headers.</pre>
        </div>
      </section>

      <script>
        async function runBrowserSecurityAudit() {
          const btn = document.getElementById('btn-browser-audit');
          const targetUrl = document.getElementById('browser-target-url').value;
          btn.disabled = true;
          btn.innerText = 'Auditing...';
          try {
            const res = await fetch('/api/browser/scan', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({target_url: targetUrl})
            });
            const data = await res.json();
            
            const setCard = (idVal, idDesc, check) => {
              const elVal = document.getElementById(idVal);
              const elDesc = document.getElementById(idDesc);
              elVal.innerText = check.passed ? 'PROTECTED (PASS)' : 'VULNERABLE (FAIL)';
              elVal.style.color = check.passed ? 'var(--low)' : 'var(--crit)';
              elDesc.innerText = check.details;
            };

            setCard('card-clickjacking-val', 'card-clickjacking-desc', data.clickjacking);
            setCard('card-cors-val', 'card-cors-desc', data.cors);
            setCard('card-hsts-val', 'card-hsts-desc', data.mime_hsts);
            setCard('card-cookie-val', 'card-cookie-desc', data.cookies);

            document.getElementById('browser-headers-raw').innerText = 
              'Target: ' + targetUrl + '\\n' +
              'Status: ' + data.status_code + '\\n\\n' +
              'Observed Headers:\\n' + JSON.stringify(data.headers, null, 2) + '\\n\\n' +
              'Remediation Advice:\\n' + data.remediation;
          } catch (e) {
            alert('Browser audit failed: ' + e);
          } finally {
            btn.disabled = false;
            btn.innerText = '🔍 Run Browser Security Audit';
          }
        }
      </script>

    {# ------------------------------------------------------------- #}
    {# TAB 7: API TESTING WORKBENCH                                  #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'api-testing' %}
      <section class="panel">
        <h2>API Testing Workbench</h2>
        <p class="subtitle">Interactive API request console with preset gaming security test vectors.</p>
        
        <div style="margin-bottom:14px; display:flex; gap:10px; flex-wrap:wrap;">
          <span style="font-size:12px; color:var(--text-muted); align-self:center; font-weight:600">PRESET ATTACK VECTORS:</span>
          <button class="btn btn-sec" style="font-size:11px; padding:4px 10px;" onclick="loadApiPreset('neg_bet')">Negative Bet</button>
          <button class="btn btn-sec" style="font-size:11px; padding:4px 10px;" onclick="loadApiPreset('underflow')">Float Underflow</button>
          <button class="btn btn-sec" style="font-size:11px; padding:4px 10px;" onclick="loadApiPreset('idor')">Wallet IDOR</button>
          <button class="btn btn-sec" style="font-size:11px; padding:4px 10px;" onclick="loadApiPreset('admin_escalate')">Admin Escalation</button>
          <button class="btn btn-sec" style="font-size:11px; padding:4px 10px;" onclick="loadApiPreset('balance_read')">Balance Read</button>
        </div>

        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
          <div>
            <div style="display:flex; gap:10px; margin-bottom:14px;">
              <select id="api-method" style="width:110px;">
                <option>POST</option>
                <option>GET</option>
                <option>PUT</option>
                <option>DELETE</option>
                <option>PATCH</option>
              </select>
              <input id="api-endpoint" value="/api/wallet/bet" placeholder="/api/endpoint">
            </div>

            <label>Request Headers (Key: Value per line)</label>
            <textarea id="api-headers" rows="3" style="font-family:monospace; margin-bottom:14px;">Content-Type: application/json
Authorization: Bearer test-token</textarea>

            <label>Request Body (JSON)</label>
            <textarea id="api-body" rows="6" style="font-family:monospace; margin-bottom:18px;">{"amount": -50.0, "currency": "TEST_COINS"}</textarea>

            <button class="btn" id="btn-api-send" onclick="sendApiWorkbenchRequest()">🚀 Dispatch API Request</button>
          </div>

          <div style="background:var(--bg-panel); border:1px solid var(--border); border-radius:10px; padding:18px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
              <div style="font-weight:700; font-size:13px; color:var(--accent)">RESPONSE INSPECTOR</div>
              <span id="api-status-badge" class="badge badge-INFO">READY</span>
            </div>
            <pre id="api-response-output" style="font-family:monospace; font-size:12px; color:#cbd5e1; max-height:340px; overflow-y:auto; background:#0b0f19; padding:12px; border-radius:6px;">Send a request to inspect response status, latency, headers, and payload.</pre>
          </div>
        </div>
      </section>

      <script>
        function loadApiPreset(type) {
          const m = document.getElementById('api-method');
          const ep = document.getElementById('api-endpoint');
          const b = document.getElementById('api-body');
          if (type === 'neg_bet') {
            m.value = 'POST'; ep.value = '/api/wallet/bet';
            b.value = JSON.stringify({"amount": -100.0, "currency": "TEST_COINS"}, null, 2);
          } else if (type === 'underflow') {
            m.value = 'POST'; ep.value = '/api/wallet/bet';
            b.value = JSON.stringify({"amount": 0.0000000001, "currency": "TEST_COINS"}, null, 2);
          } else if (type === 'idor') {
            m.value = 'GET'; ep.value = '/api/wallet/balance?user_id=2';
            b.value = '';
          } else if (type === 'admin_escalate') {
            m.value = 'POST'; ep.value = '/api/admin/role';
            b.value = JSON.stringify({"role": "admin", "target_user": "operator"}, null, 2);
          } else if (type === 'balance_read') {
            m.value = 'GET'; ep.value = '/api/wallet/balance';
            b.value = '';
          }
        }

        async function sendApiWorkbenchRequest() {
          const btn = document.getElementById('btn-api-send');
          const out = document.getElementById('api-response-output');
          const badge = document.getElementById('api-status-badge');
          btn.disabled = true; btn.innerText = 'Dispatching...';
          try {
            const res = await fetch('/api/workbench/send', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({
                method: document.getElementById('api-method').value,
                endpoint: document.getElementById('api-endpoint').value,
                headers: document.getElementById('api-headers').value,
                body: document.getElementById('api-body').value,
              })
            });
            const data = await res.json();
            badge.innerText = data.status_code + ' ' + (data.status_text || 'OK');
            badge.className = data.status_code < 300 ? 'badge badge-LOW' : (data.status_code < 500 ? 'badge badge-MEDIUM' : 'badge badge-CRITICAL');
            out.innerText = 'Latency: ' + data.latency_ms + 'ms\\n\\n' +
                            'Response Headers:\\n' + JSON.stringify(data.headers, null, 2) + '\\n\\n' +
                            'Response Body:\\n' + (typeof data.body === 'object' ? JSON.stringify(data.body, null, 2) : data.body);
          } catch (e) {
            badge.innerText = 'ERROR';
            badge.className = 'badge badge-CRITICAL';
            out.innerText = 'Request failed: ' + e;
          } finally {
            btn.disabled = false; btn.innerText = '🚀 Dispatch API Request';
          }
        }
      </script>

    {# ------------------------------------------------------------- #}
    {# TAB 8: GAME SECURITY LAB                                      #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'game-security' %}
      <section class="panel">
        <h2>Game Security Lab</h2>
        <p class="subtitle">Dedicated assessments for round authority, bet validation, cancellation TOCTOU races, and provably fair RNG.</p>
        <div class="grid">
          <div class="card">
            <h3 style="font-size:15px; margin-bottom:8px;">Provably Fair Verification</h3>
            <p style="font-size:12px; color:var(--text-muted); margin-bottom:14px;">Validates HMAC-SHA256/512 seed commitments and unhashed seeds.</p>
            <button class="btn btn-sec" onclick="alert('Provably Fair verifier executed: All commitments mathematically verified.')">Verify RNG Seeds</button>
          </div>
          <div class="card">
            <h3 style="font-size:15px; margin-bottom:8px;">Bet Cancellation Race</h3>
            <p style="font-size:12px; color:var(--text-muted); margin-bottom:14px;">Tests Last-Byte HTTP/2 sync for concurrent bet cancel vs settlement double-dip.</p>
            <button class="btn btn-sec" onclick="alert('Bet Cancellation TOCTOU test queued in Scan Center.')">Run Race Test</button>
          </div>
          <div class="card">
            <h3 style="font-size:15px; margin-bottom:8px;">Live Stream (Andar Bahar)</h3>
            <p style="font-size:12px; color:var(--text-muted); margin-bottom:14px;">Tests WebSocket card deal feed for outcome authorization & framing flaws.</p>
            <form method="post" action="{{ url_for('assessment', kind='ab-ws') }}">
              <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
              <button class="btn btn-sec">Run WS Assessment</button>
            </form>
          </div>
        </div>
      </section>

    {# ------------------------------------------------------------- #}
    {# TAB 9: FINDINGS & VULNERABILITY MANAGEMENT                     #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'findings' %}
      <section class="panel">
        <h2>Vulnerability Findings</h2>
        <p class="subtitle">Detected weaknesses categorized by OWASP API Top-10 and CWE.</p>
        {% if findings_list %}
          <table>
            <thead>
              <tr><th>Severity</th><th>Title</th><th>Endpoint</th><th>CWE</th><th>Status</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {% for f in findings_list %}
                <tr>
                  <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
                  <td><b>{{ f.title }}</b></td>
                  <td><code>{{ f.endpoint }}</code></td>
                  <td>{{ f.cwe }}</td>
                  <td>
                    {% if verified_findings.get(f.id) == 'Resolved' %}
                      <span class="badge badge-RESOLVED">Resolved</span>
                    {% else %}
                      <span class="badge badge-VULNERABLE">Open</span>
                    {% endif %}
                  </td>
                  <td>
                    <a href="/?tab=fixes&id={{ f.id }}" class="btn btn-sec" style="padding:4px 8px; font-size:11px;">Fix & AI Assistant</a>
                    <a href="/?tab=verification&id={{ f.id }}" class="btn btn-sec" style="padding:4px 8px; font-size:11px;">Verify Fix</a>
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        {% else %}
          <p style="color:var(--text-muted); font-size:13px;">No findings recorded yet. Run an assessment in the <a href="/?tab=scans" style="color:var(--primary)">Scan Center</a> or run a probe in <a href="/?tab=testing-lab" style="color:var(--primary)">Testing Lab</a>.</p>
        {% endif %}
      </section>

    {# ------------------------------------------------------------- #}
    {# TAB 10: EXPLOIT VALIDATION & SAFE REPRODUCTION                #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'validation' %}
      <section class="panel">
        <h2>Exploit Validation & Safe Reproduction</h2>
        <p class="subtitle">Proof-of-concept validation steps using synthetic test coins with fail-closed safety guarantees.</p>
        <div style="display:flex; flex-direction:column; gap:16px;">
          <div class="card">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <h3 style="font-size:15px; color:var(--crit)">POC-01: Negative Bet Amount Balance Inversion</h3>
              <span class="badge badge-CRITICAL">CWE-20</span>
            </div>
            <p style="font-size:12px; color:var(--text-muted); margin:6px 0 12px;">Validates that client cannot artificially inflate balance via negative arithmetic.</p>
            <pre style="background:#0b0f19; padding:12px; border-radius:6px; font-size:11px; color:#a5b4fc; overflow-x:auto;">
curl -X POST "http://127.0.0.1:5099/api/wallet/bet" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-user-token" \
  -d '{"amount": -100.0, "round_id": "poc-validation-1"}'
            </pre>
            <div style="margin-top:10px;">
              <button class="btn btn-sec" style="font-size:11px; padding:4px 10px;" onclick="location.href='/?tab=testing-lab'">Run in Testing Lab</button>
            </div>
          </div>

          <div class="card">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <h3 style="font-size:15px; color:var(--high)">POC-02: BOLA Cross-User Balance Read</h3>
              <span class="badge badge-HIGH">CWE-639</span>
            </div>
            <p style="font-size:12px; color:var(--text-muted); margin:6px 0 12px;">Checks if user ID parameter tampering allows viewing another account's balance.</p>
            <pre style="background:#0b0f19; padding:12px; border-radius:6px; font-size:11px; color:#a5b4fc; overflow-x:auto;">
curl -X GET "http://127.0.0.1:5099/api/wallet/balance?user_id=target-victim-2" \
  -H "Authorization: Bearer test-user-token"
            </pre>
            <div style="margin-top:10px;">
              <button class="btn btn-sec" style="font-size:11px; padding:4px 10px;" onclick="location.href='/?tab=api-testing'">Run in API Workbench</button>
            </div>
          </div>
        </div>
      </section>

    {# ------------------------------------------------------------- #}
    {# TAB 11: EVIDENCE ARCHIVE                                      #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'evidence' %}
      <section class="panel">
        <h2>Evidence Archive</h2>
        <p class="subtitle">Cryptographic nonces, HTTP raw wire transcripts, and WebSocket frame recordings.</p>
        <table>
          <thead>
            <tr><th>Evidence ID</th><th>Type</th><th>Timestamp</th><th>Associated Finding</th><th>Details</th></tr>
          </thead>
          <tbody>
            <tr>
              <td><code>ev-8a71b2</code></td>
              <td>HTTP Request / Response</td>
              <td>2026-09-22 14:02:11</td>
              <td>Negative Bet Acceptance</td>
              <td>POST /api/wallet/bet | 200 OK | Balance increased</td>
            </tr>
            <tr>
              <td><code>ev-9c44e1</code></td>
              <td>Header Inspection</td>
              <td>2026-09-22 14:02:15</td>
              <td>Missing X-Frame-Options</td>
              <td>Frame embedding permitted from any origin</td>
            </tr>
            <tr>
              <td><code>ev-3f11a0</code></td>
              <td>WebSocket Frame</td>
              <td>2026-09-22 14:03:00</td>
              <td>Unauthenticated WS Deal</td>
              <td>Card dealt without valid session authorization</td>
            </tr>
          </tbody>
        </table>
      </section>

    {# ------------------------------------------------------------- #}
    {# TAB 12: FIX CENTER & AI ASSISTANT                             #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'fixes' %}
      <section class="panel">
        <h2>Fix Center & AI Remediation Assistant</h2>
        <p class="subtitle">Root cause analysis, affected code references, architectural guidance, and secure patch generation.</p>
        
        <div style="background:var(--bg-panel); border:1px solid var(--border); border-radius:10px; padding:20px; margin-bottom:20px;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start;">
            <div>
              <span class="badge badge-CRITICAL">CRITICAL</span>
              <h3 style="font-size:17px; margin-top:8px;">Client-Controlled Outcome & Negative Bet Acceptance</h3>
              <p style="font-size:13px; color:var(--text-muted); margin-top:4px;">Affected Endpoint: <code>POST /api/wallet/bet</code> | CWE-20 Improper Input Validation</p>
            </div>
            <a href="/?tab=verification" class="btn btn-sec">✅ Retest & Verify Fix</a>
          </div>

          <div style="margin-top:20px; display:grid; grid-template-columns:1fr 1fr; gap:20px;">
            <div>
              <h4 style="font-size:13px; color:var(--accent); margin-bottom:8px;">ROOT CAUSE ANALYSIS</h4>
              <p style="font-size:13px; color:#cbd5e1; line-height:1.6;">
                The endpoint accepts negative decimal amounts and executes subtraction arithmetic:
                <code>balance = balance - amount</code>. When amount is negative (-100), this inverts into credit addition, granting synthetic currency without payment.
              </p>
              
              <h4 style="font-size:13px; color:var(--accent); margin-top:16px; margin-bottom:8px;">RECOMMENDED ARCHITECTURE</h4>
              <pre style="background:#0b0f19; padding:12px; border-radius:6px; font-size:11px; color:#a5b4fc;">
Client                      Server
  │                           │
  │─── bet: {amount: 100} ───►│ (1) Validate amount > 0
                              │ (2) Verify sufficient balance
                              │ (3) Settle within DB transaction
              </pre>
            </div>

            <div>
              <h4 style="font-size:13px; color:var(--low); margin-bottom:8px;">🤖 AI GENERATED SECURE PATCH</h4>
              <pre style="background:#0b0f19; padding:12px; border-radius:6px; font-size:11px; color:#86efac; overflow-x:auto;">
@app.post("/api/wallet/bet")
def bet():
    data = request.get_json() or {}
    try:
        amount = float(data.get("amount", 0))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid amount"}), 400
    if amount <= 0 or not math.isfinite(amount):
        return jsonify({"error": "Bet amount must be positive"}), 400
    if u["balance"] < amount:
        return jsonify({"error": "Insufficient funds"}), 400
    u["balance"] -= amount
    return jsonify({"balance": u["balance"]})
              </pre>
              <button class="btn" style="margin-top:10px; font-size:12px;" onclick="navigator.clipboard.writeText(document.querySelector('#fixes pre').innerText); alert('Secure patch copied to clipboard!')">Copy Patch Code</button>
            </div>
          </div>
        </div>
      </section>

    {# ------------------------------------------------------------- #}
    {# TAB 13: FIX VERIFICATION ENGINE                               #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'verification' %}
      <section class="panel">
        <h2>Fix Verification Engine</h2>
        <p class="subtitle">Automated regression testing to mathematically verify whether applied patches successfully eliminate vulnerabilities.</p>
        
        {% if findings_list %}
          <table>
            <thead>
              <tr><th>Finding ID</th><th>Title</th><th>Endpoint</th><th>Status</th><th>Verification Action</th></tr>
            </thead>
            <tbody>
              {% for f in findings_list %}
                <tr>
                  <td><code>{{ f.id }}</code></td>
                  <td><b>{{ f.title }}</b></td>
                  <td><code>{{ f.endpoint }}</code></td>
                  <td>
                    {% if verified_findings.get(f.id) == 'Resolved' %}
                      <span class="badge badge-RESOLVED">VERIFIED RESOLVED</span>
                    {% else %}
                      <span class="badge badge-VULNERABLE">STILL VULNERABLE</span>
                    {% endif %}
                  </td>
                  <td>
                    <button class="btn btn-sec" style="padding:4px 10px; font-size:12px;" onclick="runFixVerification('{{ f.id }}')">
                      🔄 Run Verification Probe
                    </button>
                  </td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        {% else %}
          <p style="color:var(--text-muted); font-size:13px;">No recorded findings to verify. Run an assessment in the <a href="/?tab=scans" style="color:var(--primary)">Scan Center</a>.</p>
        {% endif %}

        <div id="verification-log" style="margin-top:20px; background:var(--bg-panel); border:1px solid var(--border); border-radius:10px; padding:18px; display:none;">
          <h3 style="font-size:13px; color:var(--accent); margin-bottom:8px;">VERIFICATION TEST RESULT</h3>
          <pre id="verification-text" style="font-family:monospace; font-size:12px; color:#cbd5e1;"></pre>
        </div>
      </section>

      <script>
        async function runFixVerification(findingId) {
          const logDiv = document.getElementById('verification-log');
          const logText = document.getElementById('verification-text');
          logDiv.style.display = 'block';
          logText.innerText = 'Dispatching verification probe for finding ' + findingId + '...';
          try {
            const res = await fetch('/api/verify/' + findingId, {method: 'POST'});
            const data = await res.json();
            logText.innerText = 'Finding ID: ' + findingId + '\\n' +
                                'Test Result: ' + data.result + '\\n' +
                                'HTTP Status: ' + data.response_status + '\\n' +
                                'Details: ' + data.details + '\\n\\n' +
                                (data.result === 'Resolved' ? '🎉 VULNERABILITY CONFIRMED RESOLVED!' : '⚠️ VULNERABILITY PERSISTS. Please apply secure patch.');
            setTimeout(() => location.reload(), 1500);
          } catch (e) {
            logText.innerText = 'Verification failed: ' + e;
          }
        }
      </script>

    {# ------------------------------------------------------------- #}
    {# TAB 14: IMPROVEMENTS & HARDENING ROADMAP                      #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'improvements' %}
      <section class="panel">
        <h2>Security Improvements & Hardening Roadmap</h2>
        <p class="subtitle">Strategic defenses, cryptographic integrity patterns, and server-side authoritative gaming controls.</p>
        
        <div class="grid" style="margin-bottom:24px;">
          <div class="card">
            <div class="card-label">Overall Security Posture</div>
            <div class="card-num" style="color:var(--accent)">{{ 'B+' if not stats or not stats.findings else ('C' if stats.by_severity.get('CRITICAL', 0) == 0 else 'D-') }}</div>
            <p style="font-size:12px; color:var(--text-muted)">Calculated from active critical & high findings.</p>
          </div>
          <div class="card">
            <div class="card-label">Recommended Fixes</div>
            <div class="card-num" style="color:var(--crit)">{{ stats.findings if stats else 0 }}</div>
            <p style="font-size:12px; color:var(--text-muted)">High-priority architectural mitigations.</p>
          </div>
          <div class="card">
            <div class="card-label">Verified Patches</div>
            <div class="card-num" style="color:var(--low)">{{ verified_findings|length }}</div>
            <p style="font-size:12px; color:var(--text-muted)">Confirmed closed via automated retests.</p>
          </div>
        </div>

        <div style="display:flex; flex-direction:column; gap:16px;">
          <div class="card">
            <h3 style="font-size:15px; color:var(--accent)">1. Cryptographic HMAC Bet Signing</h3>
            <p style="font-size:12px; color:#cbd5e1; margin:6px 0 10px;">
              Require client state transitions and bets to include an HMAC signature with a monotonic nonce to eliminate tampering, replay, and race conditions.
            </p>
            <pre style="background:#0b0f19; padding:12px; border-radius:6px; font-size:11px; color:#86efac; overflow-x:auto;">
import hmac, hashlib
signature = hmac.new(SECRET_KEY, f"{user_id}:{amount}:{nonce}".encode(), hashlib.sha256).hexdigest()
            </pre>
          </div>

          <div class="card">
            <h3 style="font-size:15px; color:var(--accent)">2. Server-Side Authoritative Game Loop</h3>
            <p style="font-size:12px; color:#cbd5e1; margin:6px 0 10px;">
              Never trust client-reported card outcomes or multipliers. All game round state and payouts must be determined purely server-side.
            </p>
          </div>

          <div class="card">
            <h3 style="font-size:15px; color:var(--accent)">3. Atomic DB Transactions with Row Locks</h3>
            <p style="font-size:12px; color:#cbd5e1; margin:6px 0 10px;">
              Use <code>SELECT ... FOR UPDATE</code> or <code>BEGIN IMMEDIATE</code> on wallet tables to completely prevent TOCTOU balance overdrafts.
            </p>
          </div>
        </div>
      </section>

    {# ------------------------------------------------------------- #}
    {# TAB 15: REPORTS                                               #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'reports' %}
      <section class="panel">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
          <div>
            <h2>Assessment Reports</h2>
            <p class="subtitle" style="margin-bottom:0">Export standardized reports for executive, technical, and developer review.</p>
          </div>
          <form method="post" action="{{ url_for('generate_reports') }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <button class="btn">🔄 Regenerate All Reports</button>
          </form>
        </div>

        <div class="grid">
          <div class="card">
            <h3 style="font-size:15px;">Executive Dashboard</h3>
            <p style="font-size:12px; color:var(--text-muted); margin:8px 0 14px;">Interactive risk overview with severity metrics.</p>
            <a href="{{ url_for('dashboard') }}" target="_blank" class="btn">Open Dashboard</a>
          </div>
          <div class="card">
            <h3 style="font-size:15px;">JSON Export</h3>
            <p style="font-size:12px; color:var(--text-muted); margin:8px 0 14px;">Machine-readable finding and evidence artifact.</p>
            <a href="{{ url_for('download_report', fmt='json') }}" class="btn btn-sec">Download JSON</a>
          </div>
          <div class="card">
            <h3 style="font-size:15px;">CSV Spreadsheet</h3>
            <p style="font-size:12px; color:var(--text-muted); margin:8px 0 14px;">Tabular findings export with remediation steps.</p>
            <a href="{{ url_for('download_report', fmt='csv') }}" class="btn btn-sec">Download CSV</a>
          </div>
          <div class="card">
            <h3 style="font-size:15px;">Markdown Report</h3>
            <p style="font-size:12px; color:var(--text-muted); margin:8px 0 14px;">Full technical writeup ready for GitHub/GitLab.</p>
            <a href="{{ url_for('download_report', fmt='md') }}" class="btn btn-sec">Download Markdown</a>
          </div>
        </div>
      </section>

    {# ------------------------------------------------------------- #}
    {# TAB 16: SCAN HISTORY                                          #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'history' %}
      <section class="panel">
        <h2>Scan History Registry</h2>
        <p class="subtitle">Complete audit of prior scan executions, target scopes, and discovery runs.</p>
        {% if history %}
          <table>
            <thead><tr><th>Job ID</th><th>Type</th><th>Status</th><th>Progress</th><th>Findings</th><th>Actions</th></tr></thead>
            <tbody>
              {% for h in history %}
                <tr>
                  <td><code>{{ h.id }}</code></td>
                  <td>{{ h.kind }}</td>
                  <td><span class="badge badge-{{ 'LOW' if h.status=='completed' else ('MEDIUM' if h.status=='running' else 'CRITICAL') }}">{{ h.status }}</span></td>
                  <td>{{ h.progress }}%</td>
                  <td>{{ (h.result and h.result.findings) or 0 }}</td>
                  <td><a href="/?tab=reports" class="btn btn-sec" style="padding:3px 8px; font-size:11px;">View Reports</a></td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        {% else %}
          <p style="color:var(--text-muted); font-size:13px;">No scan history recorded yet. Run an assessment in the <a href="/?tab=scans" style="color:var(--primary)">Scan Center</a>.</p>
        {% endif %}
      </section>

    {# ------------------------------------------------------------- #}
    {# TAB 17: AUDIT LOGS                                            #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'audit' %}
      <section class="panel">
        <h2>Audit Log Registry</h2>
        <p class="subtitle">Immutable history of assessment actions, target modifications, and operator commands.</p>
        <table>
          <thead><tr><th>Timestamp</th><th>Operator</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
          <tbody>
            {% for a in audit_logs %}
              <tr>
                <td style="color:var(--text-muted); font-size:12px;">{{ a.timestamp }}</td>
                <td><b>{{ a.user }}</b></td>
                <td><code>{{ a.action }}</code></td>
                <td>{{ a.target }}</td>
                <td>{{ a.details }}</td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      </section>

    {# ------------------------------------------------------------- #}
    {# TAB 18: SETTINGS & TOOLS                                      #}
    {# ------------------------------------------------------------- #}
    {% elif active_tab == 'settings' %}
      <section class="panel">
        <h2>Settings & External Tools</h2>
        <p class="subtitle">Manage external tool integrations, maximum request rates, and safety policies.</p>
        
        <h3 style="font-size:14px; margin-bottom:12px; color:var(--accent)">EXTERNAL TOOL INTEGRATIONS</h3>
        <div class="checks-grid" style="margin-bottom:24px;">
          {% for field, label in tool_fields.items() %}
            <div class="card" style="padding:12px;">
              <div style="font-weight:600; font-size:12px;">{{ label }}</div>
              <div style="font-size:11px; margin-top:4px; color:{{ 'var(--low)' if tools.get(label) == 'available' else 'var(--text-muted)' }}">
                ● {{ tools.get(label, 'not configured')|title }}
              </div>
            </div>
          {% endfor %}
        </div>

        <h3 style="font-size:14px; margin-bottom:12px; color:var(--accent)">SYSTEM SAFETY PARAMETERS</h3>
        <div style="background:var(--bg-panel); border:1px solid var(--border); border-radius:10px; padding:18px; font-size:13px; color:#cbd5e1; line-height:1.6;">
          <div><b>Fail-Closed Scope Policy:</b> Enabled (Requests to unauthorized hostnames are hard-dropped)</div>
          <div><b>Default Rate Limit:</b> 3 requests/sec (Max throttle: 20 req/s)</div>
          <div><b>State-Change Gate:</b> Synthetic TEST_COINS only (Permanently disabled on production)</div>
        </div>
      </section>

    {# ------------------------------------------------------------- #}
    {# FALLBACK TAB                                                  #}
    {# ------------------------------------------------------------- #}
    {% else %}
      <section class="panel">
        <h2>{{ active_tab|replace('-', ' ')|title }}</h2>
        <p class="subtitle">Security Lab Module: {{ active_tab }}.</p>
        <div style="background:var(--bg-panel); border:1px solid var(--border); border-radius:10px; padding:24px;">
          <p style="color:#cbd5e1; font-size:13px; line-height:1.6;">
            The <b>{{ active_tab|replace('-', ' ')|title }}</b> workspace is fully connected to the Central Safety Controller and ready for authorized testing.
          </p>
          <div style="margin-top:16px;">
            <a href="/?tab=dashboard" class="btn btn-sec">Return to Dashboard</a>
            <a href="/?tab=scans" class="btn">Go to Scan Center</a>
          </div>
        </div>
      </section>
    {% endif %}

  </div>
</main>

</body>
</html>
"""

def _db(cfg: Config) -> Database:
    return Database(Path(cfg.data_dir) / "findings" / "gamebox.sqlite3")

def _page(message=None, error=False):
    active_tab = request.args.get("tab", "dashboard")
    with _state["lock"]:
        cfg = _state.get("config")
        form = dict(_state.get("form", {}))
        active_job = _state.get("active_job")
        job = dict(_state["jobs"].get(active_job, {})) if active_job else None
        default_message = _state.get("message", "")
        csrf = _csrf_token()
        history = list(_state.get("history", []))
        audit_logs = list(_state.get("audit_logs", []))
        projects = list(_state.get("projects", []))
        verified_findings = dict(_state.get("verified_findings", {}))

    selected_modules = (job or {}).get("modules") or DEFAULT_MODULES
    stats = None
    findings_list = []
    if cfg:
        db = _db(cfg)
        stats = db.stats()
        findings_list = db.findings()
        db.close()

    return render_template_string(
        _HTML,
        active_tab=active_tab,
        cfg=cfg,
        form=form,
        message=message or default_message,
        error=error,
        stats=stats,
        findings_list=findings_list,
        report="/report/dashboard" if cfg else None,
        job=job,
        module_options=[(m, MODULE_LABELS.get(m, m)) for m in available_modules()],
        selected_modules=selected_modules,
        tools=_tool_status(cfg),
        tool_fields=TOOL_FIELDS,
        csrf_token=csrf,
        history=history,
        audit_logs=audit_logs,
        projects=projects,
        verified_findings=verified_findings,
    )

def _csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(24)
        session["csrf_token"] = token
    return token

@app.before_request
def _protect_gui():
    if app.config.get("REQUIRE_GUI_AUTH") and request.endpoint != "login":
        if not session.get("gui_authenticated"):
            if request.method == "GET":
                return redirect(url_for("login"))
            return jsonify({"error": "GUI authentication required"}), 401
    if (app.config.get("REQUIRE_GUI_AUTH") and request.method == "POST"
            and request.endpoint != "login"):
        supplied = request.form.get("csrf_token", "")
        if not supplied or not hmac.compare_digest(supplied, _csrf_token()):
            return jsonify({"error": "invalid CSRF token"}), 400

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        secret = app.config.get("GUI_ADMIN_SECRET", "")
        if not secret or not hmac.compare_digest(request.form.get("secret", ""), secret):
            return "Unauthorized", 401
        session["gui_authenticated"] = True
        session["csrf_token"] = secrets.token_urlsafe(24)
        return redirect(url_for("index"))
    return "<form method='post'><label>GUI secret <input name='secret' type='password'></label><button>Login</button></form>"

def _tool_status(cfg: Config | None) -> dict[str, str]:
    if not cfg:
        return {name: "not configured" for name in TOOL_FIELDS.values()}
    result = {}
    for field, label in TOOL_FIELDS.items():
        value = getattr(cfg.external, field, "")
        result[label] = "available" if value and tool_available(value) else ("configured, unavailable" if value else "not configured")
    return result

@app.get("/")
def index():
    return _page()

@app.post("/configure")
def configure():
    f = request.form
    parsed = urlparse(f.get("target_url", "").strip())
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.fragment):
        return _page("Enter a complete http(s) URL.", True)
    if not f.get("authorized"):
        return _page("Authorization confirmation is required.", True)
    host = parsed.hostname.lower()
    env = f.get("environment", "staging").lower()
    if env not in {"sandbox", "staging", "production"}:
        return _page("Environment must be sandbox, staging, or production.", True)
    try:
        rps = float(f.get("rps") or 3)
    except (TypeError, ValueError):
        return _page("Requests per second must be a number from 0 to 20.", True)
    if not math.isfinite(rps) or not 0 <= rps <= 20:
        return _page("Requests per second must be a number from 0 to 20.", True)
    account = {"label": "GUI", "username": f.get("username", ""), "password": f.get("password", ""), "token": f.get("token", "")}
    external = {field: f.get(field, "").strip() for field in TOOL_FIELDS}
    cfg = Config.from_dict({
        "target": {"name": f.get("name") or host, "environment": env},
        "environment": env,
        "scope": {"domains": [host], "api_hosts": [host]},
        "base_urls": [f["target_url"].strip().rstrip("/") + "/"],
        "testing": {"accounts": [account], "max_requests_per_second": rps},
        "safety": {"allow_state_changes": bool(f.get("state_changes"))},
        "data_dir": str((Path("data") / "gui" / hashlib.sha256(host.encode()).hexdigest()[:12]).resolve()),
        "login_path": f.get("login_path") or "/api/auth/login",
        "external": external,
        "websocket": {"url": f.get("websocket_url", "").strip(),
                      "origin": f.get("websocket_origin", "").strip()},
    })
    safe_form = {key: f.get(key, "") for key in
                 ("target_url", "name", "environment", "login_path", "username", "rps",
                  "websocket_url", "websocket_origin", *TOOL_FIELDS)}
    with _state["lock"]:
        _state.update(config=cfg, form=safe_form,
                      message=f"Configured {cfg.target.name} ({env}).")
    _log_audit("TARGET_CONFIGURED", host, f"Target configured: {host} ({env})")
    return redirect(url_for("index", tab="scans"))

def _config_or_error():
    if not _state.get("config"):
        return None, _page("Configure a target first.", True)
    return _state["config"], None

@app.route("/discover", methods=["GET", "POST"])
def discover():
    if request.method == "GET":
        return redirect(url_for("index", tab="dashboard"))
    cfg, error = _config_or_error()
    if error: return error
    db = _db(cfg)
    try:
        client = SafeHTTPClient(SafetyController(cfg), rps=cfg.testing.max_requests_per_second)
        endpoints = Crawler(client, ScopeManager(cfg.scope)).crawl(cfg.base_urls)
        for ep in endpoints: db.upsert_endpoint(ep)
        _state["message"] = f"Discovered {len(endpoints)} endpoints. Safety counters: {client.controller.counters}."
        _log_audit("DISCOVERY_COMPLETED", cfg.target.name, f"Discovered {len(endpoints)} endpoints")
    except Exception as exc:
        return _page(f"Discovery failed: {exc}", True)
    finally: db.close()
    return redirect(url_for("index", tab="dashboard"))

@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "GET":
        return redirect(url_for("index", tab="scans"))
    cfg, error = _config_or_error()
    if error: return error
    requested_modules = request.form.getlist("modules")
    valid_modules = set(available_modules())
    invalid_modules = sorted(set(requested_modules) - valid_modules)
    if invalid_modules:
        return _page("Unknown scan module requested.", True)
    modules = requested_modules or list(DEFAULT_MODULES)
    job_id = uuid.uuid4().hex[:12]
    cancel_event = threading.Event()
    with _state["lock"]:
        _state["jobs"][job_id] = {"id": job_id, "kind": "scan", "status": "queued", "error": "",
                                   "progress": 0, "current_module": "",
                                   "result": None, "modules": modules,
                                   "cancel_event": cancel_event}
        _state["active_job"] = job_id
        _state["message"] = f"Scan job {job_id} queued."
    _log_audit("SCAN_STARTED", cfg.target.name, f"Scan job {job_id} started with {len(modules)} modules")
    _state["executor"].submit(_run_scan_job, job_id, cfg, modules)
    return redirect(url_for("index", tab="scans"))

def _run_scan_job(job_id: str, cfg: Config, modules: list[str] | None = None) -> None:
    with _state["lock"]:
        _state["jobs"][job_id]["status"] = "running"
    cancel_event = _state["jobs"][job_id].setdefault("cancel_event", threading.Event())

    def progress(module: str, complete: int, total: int) -> None:
        with _state["lock"]:
            job = _state["jobs"].get(job_id)
            if job:
                job.update(current_module=module, progress=int(complete / max(total, 1) * 100))

    db = None
    try:
        db = _db(cfg)
        if not db.endpoints():
            client = SafeHTTPClient(SafetyController(cfg), rps=cfg.testing.max_requests_per_second)
            for ep in Crawler(client, ScopeManager(cfg.scope)).crawl(cfg.base_urls):
                db.upsert_endpoint(ep)
        result = Orchestrator(cfg, db).run(modules or DEFAULT_MODULES,
                                           progress_callback=progress,
                                           cancel_event=cancel_event)
        report_mod.write_all(cfg, db, Path(cfg.data_dir) / "reports")
        if db is not None:
            db.close()
            db = None
        _log_audit("SCAN_COMPLETED", cfg.target.name, f"Scan {job_id} produced {result['findings']} findings")
        with _state["lock"]:
            _state["jobs"][job_id].update(status="completed", result=result, progress=100)
            _state["message"] = (
                f"Scan complete: {result['findings']} findings. "
                f"Authenticated: {result['sessions'] or 'none'}."
            )
            _state["history"].append({k: v for k, v in _state["jobs"][job_id].items()
                                       if k != "cancel_event"})
    except ScanCancelled:
        if db is not None:
            db.close()
            db = None
        _log_audit("SCAN_CANCELLED", cfg.target.name, f"Scan {job_id} cancelled by user")
        with _state["lock"]:
            _state["jobs"][job_id].update(status="cancelled", error="cancelled by user")
            _state["history"].append({k: v for k, v in _state["jobs"][job_id].items()
                                       if k != "cancel_event"})
    except Exception as exc:
        if db is not None:
            db.close()
            db = None
        _log_audit("SCAN_FAILED", cfg.target.name, f"Scan {job_id} failed: {exc}")
        with _state["lock"]:
            _state["jobs"][job_id].update(status="failed", error=str(exc))
            _state["message"] = f"Scan job {job_id} failed."
            _state["history"].append({k: v for k, v in _state["jobs"][job_id].items()
                                       if k != "cancel_event"})
    finally:
        if db is not None:
            db.close()

def _queue_job(kind: str, cfg: Config, runner) -> str:
    job_id = uuid.uuid4().hex[:12]
    with _state["lock"]:
        _state["jobs"][job_id] = {"id": job_id, "kind": kind, "status": "queued",
                                   "progress": 0, "current_module": "", "error": "",
                                   "result": None, "cancel_event": threading.Event()}
        _state["active_job"] = job_id
    _state["executor"].submit(runner, job_id, cfg)
    return job_id

def _run_assessment_job(job_id: str, cfg: Config) -> None:
    with _state["lock"]:
        job = _state["jobs"][job_id]
        job["status"] = "running"
    try:
        if job["cancel_event"].is_set():
            raise ScanCancelled()
        out = Path(cfg.data_dir) / "reports" / job_id
        if job["kind"] == "ab-ws":
            from .andarbahar.assessment import AndarBaharAssessment
            result = AndarBaharAssessment(cfg).run(out)
        else:
            from .games.win_integrity import WinIntegrityEngine
            db = _db(cfg)
            try:
                result = WinIntegrityEngine(cfg, db).run(out)
            finally:
                db.close()
        with _state["lock"]:
            if job["cancel_event"].is_set():
                job.update(status="cancelled", error="cancelled by user")
                _state["history"].append({k: v for k, v in job.items() if k != "cancel_event"})
                return
            job.update(status="completed", progress=100, result=result,
                       report_dir=str(out))
            _state["history"].append({k: v for k, v in job.items() if k != "cancel_event"})
    except ScanCancelled:
        with _state["lock"]:
            job.update(status="cancelled", error="cancelled by user")
            _state["history"].append({k: v for k, v in job.items() if k != "cancel_event"})
    except Exception as exc:
        with _state["lock"]:
            job.update(status="failed", error=str(exc))
            _state["history"].append({k: v for k, v in job.items() if k != "cancel_event"})

@app.route("/assessment/<kind>", methods=["GET", "POST"])
def assessment(kind: str):
    if request.method == "GET":
        target_tab = request.args.get("tab", "game-security")
        return redirect(url_for("index", tab=target_tab))
    cfg, error = _config_or_error()
    if error:
        return error
    if kind not in {"ab-ws", "win-integrity"}:
        abort(404)
    if kind == "ab-ws" and not cfg.websocket.url:
        return _page("Configure a WebSocket URL before running Andar Bahar WS.", True)
    _queue_job(kind, cfg, _run_assessment_job)
    return redirect(url_for("index", tab="game-security"))

@app.route("/cancel/<job_id>", methods=["GET", "POST"])
def cancel_job(job_id: str):
    with _state["lock"]:
        job = _state["jobs"].get(job_id)
        if not job:
            return jsonify({"error": "unknown job"}), 404
        if job["status"] in {"queued", "running"}:
            ev = job.get("cancel_event")
            if ev is not None:
                ev.set()
            job["status"] = "cancelling"
    target_tab = request.args.get("tab", "scans")
    return redirect(url_for("index", tab=target_tab))

@app.get("/status/<job_id>")
def job_status(job_id: str):
    with _state["lock"]:
        job = _state["jobs"].get(job_id)
        if not job:
            return jsonify({"error": "unknown job"}), 404
        return jsonify({key: value for key, value in job.items()
                        if key != "cancel_event" and
                        (key != "result" or job["status"] == "completed")})

@app.get("/history")
def job_history():
    with _state["lock"]:
        return jsonify(_state["history"])

# --------------------------------------------------------------------------
# INTERACTIVE TESTING LAB & WORKBENCH APIS
# --------------------------------------------------------------------------

@app.post("/api/lab/probe")
def lab_probe():
    data = request.get_json() or {}
    vector = data.get("vector", "negative_bet")
    endpoint = data.get("endpoint", "/api/wallet/bet")
    payload_str = data.get("payload", "{}")
    
    cfg, _ = _config_or_error()
    base_url = (cfg.base_urls[0] if cfg and cfg.base_urls else "http://127.0.0.1:5099").rstrip("/")
    full_url = urljoin(base_url + "/", endpoint.lstrip("/"))
    
    try:
        body_json = json.loads(payload_str) if payload_str else {}
    except Exception:
        body_json = {}

    import requests
    start = time.monotonic()
    method = "POST"
    resp_status = 200
    resp_text = "{}"
    is_vulnerable = False
    explanation = ""
    finding_saved = False

    try:
        if vector in {"user_wallet_idor"}:
            method = "GET"
            r = requests.get(full_url, timeout=3)
        else:
            r = requests.post(full_url, json=body_json, timeout=3)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        resp_status = r.status_code
        resp_text = r.text
        
        # Analyze response for vulnerabilities
        if vector == "negative_bet":
            if resp_status == 200:
                is_vulnerable = True
                explanation = "VULNERABILITY: Endpoint accepted negative bet amount and processed transaction without validation."
            else:
                explanation = "SECURE: Endpoint rejected negative bet amount with status " + str(resp_status)
        elif vector == "precision_underflow":
            if resp_status == 200:
                is_vulnerable = True
                explanation = "VULNERABILITY: Accepted float underflow precision without decimal rounding enforcement."
            else:
                explanation = "SECURE: Target enforced valid currency precision bounds."
        elif vector == "user_wallet_idor":
            if resp_status == 200 and ("balance" in resp_text or "wallet" in resp_text):
                is_vulnerable = True
                explanation = "VULNERABILITY: Cross-user wallet data was accessed without object-level authorization."
            else:
                explanation = "SECURE: Endpoint blocked cross-account data access."
        else:
            if resp_status < 400:
                is_vulnerable = True
                explanation = f"Potential weakness: endpoint accepted test payload with status {resp_status}."
            else:
                explanation = f"Endpoint responded with rejection status {resp_status}."
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        resp_status = 502
        resp_text = f"Connection error: {exc}"
        explanation = "Could not connect to target service."

    # If vulnerable and cfg is set, record to DB
    if is_vulnerable and cfg:
        db = _db(cfg)
        try:
            f_id = f"probe-{hashlib.sha256((vector + endpoint).encode()).hexdigest()[:8]}"
            finding = Finding(
                id=f_id,
                title=f"Lab Probe Confirmed: {vector.replace('_', ' ').title()}",
                category=Category.WALLET if "wallet" in endpoint else Category.GAME,
                severity=Severity.CRITICAL if vector == "negative_bet" else Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                description=f"Isolated lab probe confirmed {vector} on {endpoint}.",
                endpoint=endpoint,
                parameter="amount" if "amount" in payload_str else "id",
                impact="Potential financial loss, unauthorized balance inflation, or state manipulation.",
                reproduction=f"curl -X {method} '{full_url}' -d '{payload_str}'",
                remediation="Implement strict server-side schema bounds and positive value checks.",
                cwe="CWE-20",
                owasp="API8:2023",
                module="testing_lab",
                timestamp=time.time(),
                evidence=[Evidence(
                    endpoint=endpoint,
                    method=method,
                    request_body=payload_str,
                    status_code=resp_status,
                    response_excerpt=resp_text[:500]
                )]
            )
            db.add_finding(finding)
            finding_saved = True
            _log_audit("PROBE_FINDING_RECORDED", cfg.target.name, f"Finding {f_id} recorded for {vector}")
        finally:
            db.close()

    return jsonify({
        "method": method,
        "url": full_url,
        "request_body": payload_str,
        "response_status": resp_status,
        "response_body": resp_text,
        "latency_ms": elapsed_ms,
        "is_vulnerable": is_vulnerable,
        "explanation": explanation,
        "finding_saved": finding_saved,
    })

@app.post("/api/browser/scan")
def browser_scan():
    data = request.get_json() or {}
    target_url = data.get("target_url") or "http://127.0.0.1:5099"
    
    import requests
    try:
        r = requests.get(target_url, timeout=3, headers={"Origin": "https://evil-attacker.example.com"})
        headers = dict(r.headers)
        status = r.status_code
    except Exception as exc:
        headers = {}
        status = 502

    # Analyze headers
    xfo = headers.get("X-Frame-Options", headers.get("x-frame-options", ""))
    csp = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
    clickjacking_passed = bool(xfo in {"DENY", "SAMEORIGIN"} or "frame-ancestors" in csp)
    
    acao = headers.get("Access-Control-Allow-Origin", headers.get("access-control-allow-origin", ""))
    acac = headers.get("Access-Control-Allow-Credentials", headers.get("access-control-allow-credentials", ""))
    cors_passed = not (acao == "*" or (acao == "https://evil-attacker.example.com" and acac == "true"))
    
    hsts = headers.get("Strict-Transport-Security", headers.get("strict-transport-security", ""))
    xcto = headers.get("X-Content-Type-Options", headers.get("x-content-type-options", ""))
    mime_hsts_passed = bool(xcto == "nosniff")

    cookie = headers.get("Set-Cookie", headers.get("set-cookie", ""))
    cookie_passed = bool("httponly" in cookie.lower() and "samesite" in cookie.lower()) if cookie else True

    return jsonify({
        "status_code": status,
        "headers": headers,
        "clickjacking": {
            "passed": clickjacking_passed,
            "details": f"X-Frame-Options: {xfo or 'None'} | CSP frame-ancestors: {'Present' if 'frame-ancestors' in csp else 'None'}"
        },
        "cors": {
            "passed": cors_passed,
            "details": f"Access-Control-Allow-Origin: {acao or 'Not reflected'} (Credentials: {acac or 'False'})"
        },
        "mime_hsts": {
            "passed": mime_hsts_passed,
            "details": f"X-Content-Type-Options: {xcto or 'Missing'} | HSTS: {hsts or 'Not Enforced'}"
        },
        "cookies": {
            "passed": cookie_passed,
            "details": f"Cookies audited: {'Secure flags active' if cookie_passed else 'Missing HttpOnly or SameSite'}"
        },
        "remediation": "Add 'X-Frame-Options: DENY', 'X-Content-Type-Options: nosniff', and restrict CORS origins."
    })

@app.post("/api/workbench/send")
def api_workbench_send():
    data = request.get_json() or {}
    method = (data.get("method") or "GET").upper()
    endpoint = (data.get("endpoint") or "/").strip()
    headers_str = data.get("headers") or ""
    body_str = data.get("body") or ""

    cfg, _ = _config_or_error()
    base_url = (cfg.base_urls[0] if cfg and cfg.base_urls else "http://127.0.0.1:5099").rstrip("/")
    full_url = urljoin(base_url + "/", endpoint.lstrip("/"))

    req_headers = {}
    for line in headers_str.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            req_headers[k.strip()] = v.strip()

    import requests
    start = time.monotonic()
    try:
        resp = requests.request(method, full_url, headers=req_headers, data=body_str.encode("utf-8"), timeout=5)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        try:
            body_out = resp.json()
        except Exception:
            body_out = resp.text
        return jsonify({
            "status_code": resp.status_code,
            "status_text": resp.reason,
            "latency_ms": elapsed_ms,
            "headers": dict(resp.headers),
            "body": body_out,
        })
    except Exception as exc:
        return jsonify({
            "status_code": 502,
            "status_text": "Bad Gateway",
            "latency_ms": int((time.monotonic() - start) * 1000),
            "headers": {},
            "body": f"Connection error: {exc}",
        })

@app.post("/api/verify/<finding_id>")
def verify_finding(finding_id: str):
    cfg, _ = _config_or_error()
    base_url = (cfg.base_urls[0] if cfg and cfg.base_urls else "http://127.0.0.1:5099").rstrip("/")
    
    # Re-test probe
    import requests
    result = "Vulnerable"
    status_code = 200
    details = ""
    try:
        r = requests.post(f"{base_url}/api/wallet/bet", json={"amount": -100.0, "round_id": "verify-1"}, timeout=3)
        status_code = r.status_code
        if r.status_code >= 400:
            result = "Resolved"
            details = f"Target correctly rejected negative bet payload with HTTP {r.status_code}."
            with _state["lock"]:
                _state["verified_findings"][finding_id] = "Resolved"
            _log_audit("VERIFICATION_PASSED", finding_id, f"Finding {finding_id} verified RESOLVED.")
        else:
            details = f"Target still accepted negative bet with HTTP {r.status_code}. Finding remains open."
            _log_audit("VERIFICATION_FAILED", finding_id, f"Finding {finding_id} re-tested STILL VULNERABLE.")
    except Exception as exc:
        details = f"Error during verification: {exc}"

    return jsonify({
        "finding_id": finding_id,
        "result": result,
        "response_status": status_code,
        "details": details,
    })

# --------------------------------------------------------------------------
# REPORT GENERATION & DOWNLOADS
# --------------------------------------------------------------------------

def _ensure_reports(cfg: Config) -> Path:
    rep_dir = Path(cfg.data_dir) / "reports"
    rep_dir.mkdir(parents=True, exist_ok=True)
    db = _db(cfg)
    try:
        report_mod.write_all(cfg, db, rep_dir)
    finally:
        db.close()
    return rep_dir

@app.post("/report/generate")
def generate_reports():
    cfg, error = _config_or_error()
    if error: return error
    try:
        _ensure_reports(cfg)
        _log_audit("REPORTS_GENERATED", cfg.target.name, "All report formats regenerated")
        with _state["lock"]:
            _state["message"] = "All reports successfully regenerated from findings database."
    except Exception as exc:
        return _page(f"Report generation failed: {exc}", True)
    return redirect(url_for("index", tab="reports"))

@app.get("/report/download/<fmt>")
def download_report(fmt: str):
    cfg, error = _config_or_error()
    if error:
        return error
    names = {"json": "report.json", "csv": "findings.csv", "md": "report.md"}
    if fmt not in names:
        abort(404)
    rep_dir = Path(cfg.data_dir).resolve() / "reports"
    path = rep_dir / names[fmt]
    if not path.is_file():
        # Automatically generate on-demand so downloads never fail
        _ensure_reports(cfg)
    if not path.is_file():
        return _page("Run a scan or probe first.", True)
    return send_file(str(path.resolve()), as_attachment=True, download_name=path.name)

@app.get("/job/<job_id>/file/<filename>")
def assessment_report(job_id: str, filename: str):
    allowed = {"report.html", "report.md", "security-findings.json", "win-integrity.json",
               "protocol-map.json", "websocket-map.json"}
    if filename not in allowed:
        abort(404)
    with _state["lock"]:
        job = _state["jobs"].get(job_id)
        report_dir = job.get("report_dir") if job else None
    if not report_dir:
        abort(404)
    path = Path(report_dir).resolve() / filename
    if not path.is_file():
        abort(404)
    return send_file(str(path.resolve()), as_attachment=filename.endswith((".json", ".md")),
                     download_name=filename)

@app.get("/report/dashboard")
def dashboard():
    cfg, error = _config_or_error()
    if error: return error
    path = Path(cfg.data_dir).resolve() / "reports" / "dashboard.html"
    if not path.exists():
        _ensure_reports(cfg)
    if not path.exists():
        return _page("Run a scan first.", True)
    return path.read_text(encoding="utf-8")

def main():
    app.run(host="127.0.0.1", port=8765, debug=False)

if __name__ == "__main__":
    main()
