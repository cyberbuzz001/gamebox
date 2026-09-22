"""Integration tests for the local browser GUI."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

import gamebox.gui as gui
from gamebox.core.database import Database
from gamebox.core.models import Category, Endpoint, RequestClass
from gamebox.safety.controller import SafetyController


@pytest.fixture()
def client(tmp_path, monkeypatch):
    executor = ThreadPoolExecutor(max_workers=1)
    monkeypatch.setattr(gui, "_db", lambda cfg: Database(tmp_path / "findings.sqlite3"))
    with gui._state["lock"]:
        gui._state.update(config=None, form={}, message="Configure a target to begin.",
                          jobs={}, active_job=None, executor=executor)
    gui.app.config.update(TESTING=True)
    gui.app.config.update(REQUIRE_GUI_AUTH=False, GUI_ADMIN_SECRET="test-gui-secret")
    with gui.app.test_client() as test_client:
        yield test_client
    executor.shutdown(wait=True)


def configure(client, **fields):
    data = {
        "target_url": "https://authorized.example",
        "environment": "staging",
        "rps": "3",
        "authorized": "on",
    }
    data.update(fields)
    return client.post("/configure", data=data)


@pytest.mark.parametrize("target_url", ["", "ftp://authorized.example", "https://u:p@authorized.example"])
def test_configure_rejects_invalid_url(client, target_url):
    response = configure(client, target_url=target_url)
    assert response.status_code == 200
    assert b"complete http(s) URL" in response.data


@pytest.mark.parametrize("rps", ["nope", "-1", "21", "NaN", "Infinity"])
def test_configure_rejects_invalid_rate_limit(client, rps):
    response = configure(client, rps=rps)
    assert response.status_code == 200
    assert b"Requests per second must be a number" in response.data


def test_configure_requires_authorization(client):
    response = client.post("/configure", data={"target_url": "https://authorized.example"})
    assert response.status_code == 200
    assert b"Authorization confirmation is required" in response.data


def test_production_forces_read_only(client):
    configure(client, environment="production", state_changes="on")
    cfg = gui._state["config"]
    decision = SafetyController(cfg).authorize(
        "POST", "https://authorized.example/api/bonus/claim", "{}"
    )
    assert decision.request_class == RequestClass.STATE_CHANGING
    assert not decision.allowed


def test_credentials_are_not_retained_in_form_or_html(client):
    password = "test-password-should-not-be-retained"
    token = "test-token-should-not-be-retained"
    response = configure(client, password=password, token=token)
    assert response.status_code == 302
    assert password not in response.data.decode()
    assert token not in response.data.decode()
    assert password not in gui._state["form"].values()
    assert token not in gui._state["form"].values()
    assert gui._state["config"].testing.accounts[0].password == password


def test_configured_scope_blocks_other_hosts(client):
    configure(client)
    cfg = gui._state["config"]
    decision = SafetyController(cfg).authorize("GET", "https://outside.example/", "")
    assert not decision.allowed
    assert "scope" in decision.reason


def test_discover_persists_endpoints(client, monkeypatch):
    endpoint = Endpoint(method="GET", url="https://authorized.example/api/profile",
                        category=Category.PROFILE)

    class FakeCrawler:
        def __init__(self, *_args):
            pass

        def crawl(self, _urls):
            return [endpoint]

    monkeypatch.setattr(gui, "Crawler", FakeCrawler)
    configure(client)
    response = client.post("/discover")
    assert response.status_code == 302
    db = gui._db(gui._state["config"])
    try:
        assert db.endpoints()[0].url == endpoint.url
    finally:
        db.close()


def test_scan_is_background_job_and_status_is_exposed(client, monkeypatch):
    started = threading.Event()
    release = threading.Event()

    class FakeOrchestrator:
        def __init__(self, *_args):
            pass

        def run(self, _modules, **_kwargs):
            started.set()
            release.wait(timeout=2)
            return {"findings": 0, "sessions": [], "modules": []}

    class FakeCrawler:
        def __init__(self, *_args):
            pass

        def crawl(self, _urls):
            return []

    monkeypatch.setattr(gui, "Orchestrator", FakeOrchestrator)
    monkeypatch.setattr(gui, "Crawler", FakeCrawler)

    def fake_write_all(_cfg, _db, report_dir):
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "dashboard.html").write_text("<h1>test dashboard</h1>", encoding="utf-8")

    monkeypatch.setattr(gui.report_mod, "write_all", fake_write_all)
    configure(client)
    began = time.monotonic()
    response = client.post("/scan")
    elapsed = time.monotonic() - began
    assert response.status_code == 302
    assert elapsed < 0.5
    assert started.wait(timeout=2)

    job_id = gui._state["active_job"]
    status = client.get(f"/status/{job_id}")
    assert status.status_code == 200
    assert status.get_json()["status"] == "running"
    release.set()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if client.get(f"/status/{job_id}").get_json()["status"] == "completed":
            break
        time.sleep(0.01)
    assert client.get(f"/status/{job_id}").get_json()["status"] == "completed"
    dashboard = client.get("/report/dashboard")
    assert dashboard.status_code == 200
    assert b"test dashboard" in dashboard.data


def test_repeated_configuration_does_not_change_queued_job(client, monkeypatch):
    captured = []
    release = threading.Event()

    def fake_job(job_id, cfg, modules):
        captured.append(cfg.target.name)
        assert modules == ["admin_access"]
        release.wait(timeout=2)
        with gui._state["lock"]:
            gui._state["jobs"][job_id]["status"] = "completed"

    monkeypatch.setattr(gui, "_run_scan_job", fake_job)
    configure(client, name="first-target")
    client.post("/scan", data={"modules": "admin_access"})
    configure(client, target_url="https://second.example", name="second-target")
    assert captured == ["first-target"]
    release.set()


def test_unknown_job_returns_404(client):
    response = client.get("/status/does-not-exist")
    assert response.status_code == 404
    assert response.get_json()["error"] == "unknown job"


def test_downloads_and_history(client, tmp_path):
    configure(client)
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    (report_dir / "report.json").write_text("{}", encoding="utf-8")
    (report_dir / "findings.csv").write_text("id\n", encoding="utf-8")
    (report_dir / "report.md").write_text("# report", encoding="utf-8")
    cfg = gui._state["config"]
    cfg.data_dir = str(tmp_path)
    for fmt in ("json", "csv", "md"):
        response = client.get(f"/report/download/{fmt}")
        assert response.status_code == 200
    assert client.get("/history").status_code == 200


def test_cancel_requests_cooperative_stop(client, monkeypatch):
    started = threading.Event()
    release = threading.Event()

    class FakeOrchestrator:
        def __init__(self, *_args):
            pass

        def run(self, _modules, **kwargs):
            started.set()
            while not kwargs["cancel_event"].is_set() and not release.is_set():
                time.sleep(0.01)
            raise gui.ScanCancelled()

    monkeypatch.setattr(gui, "Orchestrator", FakeOrchestrator)
    monkeypatch.setattr(gui, "Crawler", lambda *_args: type("C", (), {"crawl": lambda *_: []})())
    configure(client)
    client.post("/scan")
    assert started.wait(timeout=2)
    job_id = gui._state["active_job"]
    response = client.post(f"/cancel/{job_id}")
    assert response.status_code == 302
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if client.get(f"/status/{job_id}").get_json()["status"] == "cancelled":
            break
        time.sleep(0.01)
    assert client.get(f"/status/{job_id}").get_json()["status"] == "cancelled"
    release.set()


def test_nonlocal_mode_requires_secret_and_csrf(client):
    gui.app.config.update(REQUIRE_GUI_AUTH=True, GUI_ADMIN_SECRET="test-gui-secret")
    assert client.get("/").status_code == 302
    login = client.post("/login", data={"secret": "test-gui-secret"})
    assert login.status_code == 302
    with client.session_transaction() as sess:
        csrf = sess["csrf_token"]
    assert client.post("/configure", data={"target_url": "https://authorized.example",
                                            "authorized": "on"}).status_code == 400
    assert client.post("/configure", data={"target_url": "https://authorized.example",
                                            "authorized": "on", "csrf_token": csrf}).status_code == 302


def test_lab_probe_endpoint(client, monkeypatch):
    configure(client)
    class FakeResponse:
        status_code = 200
        text = '{"balance": 1100.0}'
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: FakeResponse())
    res = client.post("/api/lab/probe",
                      json={"vector": "negative_bet", "endpoint": "/api/wallet/bet",
                            "payload": '{"amount": -100.0}'})
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_vulnerable"] is True
    assert data["finding_saved"] is True


def test_browser_scan_endpoint(client, monkeypatch):
    class FakeHeadResponse:
        status_code = 200
        headers = {"Server": "Apache", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"}
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: FakeHeadResponse())
    res = client.post("/api/browser/scan", json={"target_url": "http://127.0.0.1:5099"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["clickjacking"]["passed"] is True
    assert data["mime_hsts"]["passed"] is True


def test_api_workbench_send(client, monkeypatch):
    configure(client)
    class FakeResp:
        status_code = 200
        reason = "OK"
        headers = {"Content-Type": "application/json"}
        def json(self):
            return {"status": "ok"}
    monkeypatch.setattr("requests.request", lambda *args, **kwargs: FakeResp())
    res = client.post("/api/workbench/send",
                      json={"method": "POST", "endpoint": "/api/wallet/bet",
                            "headers": "Content-Type: application/json", "body": '{"amount": 10}'})
    assert res.status_code == 200
    assert res.get_json()["status_code"] == 200


def test_verify_finding_endpoint(client, monkeypatch):
    configure(client)
    class FakeRecheck:
        status_code = 400
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: FakeRecheck())
    res = client.post("/api/verify/probe-12345")
    assert res.status_code == 200
    data = res.get_json()
    assert data["result"] == "Resolved"


def test_generate_reports_endpoint(client):
    configure(client)
    res = client.post("/report/generate")
    assert res.status_code == 302

