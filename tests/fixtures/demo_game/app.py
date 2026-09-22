"""GAMEBOX demo target: an intentionally-vulnerable gaming app.

FOR AUTHORIZED LOCAL TESTING ONLY.
  * Binds to 127.0.0.1 only. Never expose this on a network.
  * Uses synthetic TEST_COINS held in memory. There is no real money, no real
    payment integration, and no persistence.
  * Vulnerabilities here are deliberate teaching material for the scanner, in
    the tradition of OWASP Juice Shop / DVWA. None of them can touch real funds.

Deliberate weaknesses (each affects only synthetic data / TEST_COINS):
  1.  IDOR on GET /api/wallet/<id>            -- no ownership check
  2.  Replayable POST /api/bonus/claim        -- no idempotency
  3.  Duplicate POST /api/game/settlement     -- same round_id credits repeatedly
  4.  Client-trusted payout on the bet        -- server credits client payout
  5.  Excessive data exposure on /api/wallet/me (password_hash, is_admin, ...)
  6.  Mass assignment on POST /api/profile/update (role/is_admin/balance)
  7.  Reflected XSS on GET /api/search?q=
  8.  SQL-injection indicator on GET /api/user?id='
  9.  Path traversal on GET /api/file?name=../
  10. SSRF on POST /api/avatar/fetch (no target validation)
  11. Broken function-level authz: GET /api/admin/users (no auth)
  12. Secret exposure on GET /api/admin/config
  13. Login user-enumeration + no rate limiting on /api/auth/login
  14. Predictable password-reset token on POST /api/auth/forgot
  15. Permissive CORS (reflects Origin + allows credentials)
  16. Missing security headers on every response
  17. Unsafe file upload on POST /api/upload (no type/extension checks)
  18. GraphQL introspection enabled + BOLA on user(id) at POST /graphql
  19. Unauthenticated WebSocket referenced at ws://.../ws/game (see /static/app.js)
  20. Unsigned + replayable payment webhook on POST /api/payment/webhook
"""
from __future__ import annotations

import datetime as _dt

from flask import Flask, jsonify, request

TEST_CURRENCY = "TEST_COINS"


def create_app() -> Flask:
    app = Flask(__name__)

    users = {
        "alice": {"user_id": 1, "wallet_id": 1001, "password": "alice-test-pw",
                  "balance": 1000, "role": "user", "is_admin": False,
                  "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
                  "email": "alice@demo.test", "internal_notes": "VIP tier 2"},
        "bob":   {"user_id": 2, "wallet_id": 1002, "password": "bob-test-pw",
                  "balance": 1000, "role": "user", "is_admin": False,
                  "password_hash": "6f1ed002ab5595859014ebf0951522d9",
                  "email": "bob@demo.test", "internal_notes": "flagged: chargeback"},
        # TEST_ADMIN: the legitimate administrator used to build the authz matrix.
        "admin": {"user_id": 9, "wallet_id": 1009, "password": "admin-test-pw",
                  "balance": 0, "role": "admin", "is_admin": True,
                  "password_hash": "21232f297a57a5a743894a0e4a801fc3",
                  "email": "admin@demo.test", "internal_notes": "platform operator"},
    }
    tokens: dict[str, str] = {}
    settled: set[str] = set()
    processed_orders: set[str] = set()
    login_attempts: list[str] = []

    def _access_token(u: dict) -> str:
        # VULN 21: unsigned "JWT-style" token -- role claim is client-forgeable.
        import base64
        import json as _j
        payload = {"uid": u["user_id"], "role": u["role"], "is_admin": u["is_admin"]}
        return base64.urlsafe_b64encode(_j.dumps(payload).encode()).decode().rstrip("=")

    def current_user():
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            uname = tokens.get(auth.split(" ", 1)[1].strip())
            if uname:
                return uname, users[uname]
        return None, None

    def require_admin():
        """Server-side admin check used by the *properly protected* endpoints."""
        uname, u = current_user()
        if not u:
            return None, (jsonify({"error": "unauthorized"}), 401)
        if not u.get("is_admin"):
            return None, (jsonify({"error": "forbidden: admin only"}), 403)
        return u, None

    @app.after_request
    def permissive_cors(resp):
        # VULN 15/16: reflects Origin, allows credentials, no security headers.
        origin = request.headers.get("Origin")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    # ---- pages / discovery surface --------------------------------------
    @app.get("/")
    def index():
        return ("<!doctype html><html><head><title>Demo Casino (TEST_COINS)</title>"
                "<script src='/static/app.js'></script></head><body>"
                "<h1>Demo Casino - TEST_COINS only</h1></body></html>")

    @app.get("/static/app.js")
    def appjs():
        js = (
            "const API = {\n"
            "  login: '/api/auth/login',\n"
            "  forgot: '/api/auth/forgot',\n"
            "  walletMe: '/api/wallet/me',\n"
            "  walletById: '/api/wallet/{id}',\n"
            "  bonusClaim: '/api/bonus/claim',\n"
            "  teenPattiBet: '/api/game/teenpatti/bet',\n"
            "  settlement: '/api/game/settlement',\n"
            "  profileUpdate: '/api/profile/update',\n"
            "  search: '/api/search',\n"
            "  user: '/api/user',\n"
            "  file: '/api/file',\n"
            "  avatarFetch: '/api/avatar/fetch',\n"
            "  upload: '/api/upload',\n"
            "  graphql: '/graphql',\n"
            "  adminUsers: '/api/admin/users',\n"
            "  adminConfig: '/api/admin/config',\n"
            "  adminSettings: '/api/admin/settings',\n"
            "  adminGames: '/api/admin/games',\n"
            "  adminReports: '/api/admin/reports',\n"
            "  adminAnalytics: '/api/admin/analytics',\n"
            "  adminWalletAdjust: '/api/admin/wallet/adjust',\n"
            "  paymentWebhook: '/api/payment/webhook',\n"
            "  gameSocket: 'ws://127.0.0.1:5099/ws/game'\n"
            "};\n"
            "// TODO(demo): remove hardcoded key api_key='demo0123456789abcdef0000'\n"
        )
        return app.response_class(js, mimetype="application/javascript")

    # ---- auth -----------------------------------------------------------
    @app.post("/api/auth/login")
    def login():
        data = request.get_json(silent=True) or {}
        login_attempts.append(data.get("username", ""))  # VULN 13: no rate limit
        u = users.get(data.get("username", ""))
        if not u:
            return jsonify({"error": "user not found"}), 404          # enumeration
        if u["password"] != data.get("password"):
            return jsonify({"error": "invalid password"}), 401        # enumeration
        import secrets as _s
        token = _s.token_hex(16)
        tokens[token] = data["username"]
        return jsonify({"token": token, "user_id": u["user_id"], "wallet_id": u["wallet_id"],
                        "role": u["role"], "access_token": _access_token(u)})

    @app.post("/api/auth/forgot")
    def forgot():
        data = request.get_json(silent=True) or {}
        u = users.get(data.get("username", ""))
        if not u:
            return jsonify({"error": "user not found"}), 404
        # VULN 14: predictable token returned in the response body.
        today = _dt.date.today().isoformat()
        token = f"reset-{u['user_id']}-{today}"
        return jsonify({"reset_token": token, "message": "use this token to reset"})

    # ---- wallet ---------------------------------------------------------
    @app.get("/api/wallet/me")
    def wallet_me():
        _, u = current_user()
        if not u:
            return jsonify({"error": "unauthorized"}), 401
        # VULN 5: excessive data exposure (returns the whole user record).
        return jsonify({"wallet_id": u["wallet_id"], "user_id": u["user_id"],
                        "balance": u["balance"], "currency": TEST_CURRENCY,
                        "password_hash": u["password_hash"], "is_admin": u["is_admin"],
                        "role": u["role"], "email": u["email"],
                        "internal_notes": u["internal_notes"]})

    @app.get("/api/wallet/<int:wallet_id>")
    def wallet_by_id(wallet_id: int):
        _, u = current_user()
        if not u:
            return jsonify({"error": "unauthorized"}), 401
        for owner in users.values():                       # VULN 1: no ownership check
            if owner["wallet_id"] == wallet_id:
                return jsonify({"wallet_id": owner["wallet_id"], "user_id": owner["user_id"],
                                "balance": owner["balance"], "currency": TEST_CURRENCY})
        return jsonify({"error": "not found"}), 404

    # ---- profile (mass assignment) --------------------------------------
    @app.post("/api/profile/update")
    def profile_update():
        _, u = current_user()
        if not u:
            return jsonify({"error": "unauthorized"}), 401
        data = request.get_json(silent=True) or {}
        for field in ("display_name", "role", "is_admin", "balance"):  # VULN 6
            if field in data:
                u[field] = data[field]
        return jsonify({"updated": True, "role": u.get("role"),
                        "is_admin": u.get("is_admin"), "balance": u["balance"]})

    # ---- bonus / game ---------------------------------------------------
    @app.post("/api/bonus/claim")
    def bonus_claim():
        _, u = current_user()
        if not u:
            return jsonify({"error": "unauthorized"}), 401
        u["balance"] += 100                                # VULN 2: replayable
        return jsonify({"claimed": 100, "balance": u["balance"], "currency": TEST_CURRENCY})

    @app.post("/api/game/teenpatti/bet")
    def teenpatti_bet():
        _, u = current_user()
        if not u:
            return jsonify({"error": "unauthorized"}), 401
        data = request.get_json(silent=True) or {}
        u["balance"] -= int(data.get("bet_amount", 0))
        payout = data.get("payout", data.get("win_amount"))
        if payout is not None:
            u["balance"] += int(payout)                    # VULN 4: client-trusted
        return jsonify({"result": data.get("result", "win"), "payout": payout,
                        "balance": u["balance"], "currency": TEST_CURRENCY})

    @app.post("/api/game/settlement")
    def settlement():
        _, u = current_user()
        if not u:
            return jsonify({"error": "unauthorized"}), 401
        data = request.get_json(silent=True) or {}
        round_id = str(data.get("round_id", ""))
        settled.add(round_id)                              # VULN 3: not enforced
        u["balance"] += 250
        return jsonify({"round_id": round_id, "credited": 250,
                        "balance": u["balance"], "currency": TEST_CURRENCY})

    @app.post("/api/wallet/negative-bet")
    def negative_bet():
        _, u = current_user()
        if not u:
            return jsonify({"error": "unauthorized"}), 401
        data = request.get_json(silent=True) or {}
        amount = float(data.get("amount", 0))
        u["balance"] -= amount                             # VULN 29: accepts negative amounts
        return jsonify({"debited": amount, "balance": u["balance"], "currency": TEST_CURRENCY})

    @app.post("/api/game/bet/cancel")
    def bet_cancel():
        _, u = current_user()
        if not u:
            return jsonify({"error": "unauthorized"}), 401
        data = request.get_json(silent=True) or {}
        u["balance"] += 100                                # VULN 30: no lock on cancellation
        return jsonify({"cancelled": True, "refunded": 100, "balance": u["balance"], "currency": TEST_CURRENCY})


    # ---- injection-family demos -----------------------------------------
    @app.get("/api/search")
    def search():
        q = request.args.get("q", "")
        # VULN 7: reflected XSS -- q echoed into HTML without escaping.
        return app.response_class(f"<html><body>Results for: {q}</body></html>",
                                  mimetype="text/html")

    @app.get("/api/user")
    def user_lookup():
        uid = request.args.get("id", "")
        if "'" in uid or '"' in uid:                       # VULN 8: SQLi indicator
            return jsonify({"error": "SQL syntax error near '" + uid +
                            "' at line 1 in SELECT * FROM users WHERE id=" + uid}), 500
        return jsonify({"id": uid, "name": "demo"})

    @app.get("/api/file")
    def file_read():
        name = request.args.get("name", "")
        if ".." in name or name.startswith("/"):           # VULN 9: path traversal
            return app.response_class(
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin",
                mimetype="text/plain")
        return app.response_class("(demo file contents)", mimetype="text/plain")

    @app.post("/api/avatar/fetch")
    def avatar_fetch():
        data = request.get_json(silent=True) or {}
        url = data.get("url", "")
        # VULN 10: SSRF -- no validation of the target. Demo does NOT actually
        # fetch; it only echoes that it would, which is enough to flag the flaw.
        return jsonify({"fetched": True, "url": url, "content_length": 0})

    @app.post("/api/upload")
    def upload():
        _, u = current_user()
        if not u:
            return jsonify({"error": "unauthorized"}), 401
        data = request.get_json(silent=True) or {}
        fname = data.get("filename", "file.bin")
        # VULN 17: no extension/content-type validation. Nothing is written to disk.
        return jsonify({"stored": True, "url": f"/uploads/{fname}",
                        "content_type": data.get("content_type", "application/octet-stream")})

    # ---- admin (broken function-level authorization) --------------------
    @app.get("/api/admin/users")
    def admin_users():
        # VULN 11: no authentication/authorization at all.
        return jsonify({"users": [
            {"user_id": u["user_id"], "email": u["email"], "balance": u["balance"],
             "role": u["role"]} for u in users.values()]})

    @app.get("/api/admin/config")
    def admin_config():
        # VULN 12: exposes secrets, no auth.
        return jsonify({"env": "sandbox", "debug": True,
                        "api_key": "demo0123456789abcdef0000",
                        "jwt_secret": "demo-jwt-secret-do-not-use"})

    # ---- admin surface: a mix of properly-protected and broken endpoints ----
    @app.get("/api/admin/settings")
    def admin_settings():
        # PROPERLY PROTECTED (server-side is_admin). Reachable only if the caller
        # is actually admin -- or after a mass-assignment privilege escalation.
        u, err = require_admin()
        if err:
            return err
        return jsonify({"maintenance_mode": False, "max_bet": 100000, "house_edge": 0.03})

    @app.get("/api/admin/games")
    def admin_games():
        u, err = require_admin()          # properly protected
        if err:
            return err
        return jsonify({"games": ["teenpatti", "rummy"], "rtp": {"teenpatti": 0.97}})

    @app.get("/api/admin/wallet/adjustments")
    def admin_wallet_adjustments():
        u, err = require_admin()          # properly protected (read-only log)
        if err:
            return err
        return jsonify({"adjustments": []})

    @app.get("/api/admin/reports")
    def admin_reports():
        # VULN 22: trusts a client-supplied role header (client-controlled role).
        if request.headers.get("X-User-Role", "").lower() == "admin":
            return jsonify({"gross_gaming_revenue": 12345, "active_users": 42})
        return jsonify({"error": "forbidden"}), 403

    @app.get("/api/admin/analytics")
    def admin_analytics():
        # VULN 21: trusts the role claim inside the unsigned access token.
        import base64
        import json as _j
        tok = request.headers.get("X-Access-Token", "")
        try:
            pad = tok + "=" * (-len(tok) % 4)
            claims = _j.loads(base64.urlsafe_b64decode(pad.encode()).decode())
        except Exception:
            claims = {}
        if claims.get("role") == "admin" or claims.get("is_admin") is True:
            return jsonify({"dau": 42, "conversion": 0.12})
        return jsonify({"error": "forbidden"}), 403

    @app.post("/api/admin/wallet/adjust")
    def admin_wallet_adjust():
        # Destructive/financial admin op. Implemented as a NO-OP for demo safety;
        # the scanner must never reach it (classified FINANCIAL/DESTRUCTIVE and
        # blocked by the safety controller). Belt-and-suspenders: it changes nothing.
        return jsonify({"would_adjust": request.get_json(silent=True) or {},
                        "note": "no-op in demo; not applied"})

    @app.delete("/api/admin/users/<int:user_id>")
    def admin_delete_user(user_id: int):
        # Destructive admin op. NO-OP in the demo; the scanner must never reach it.
        return jsonify({"would_delete": user_id, "note": "no-op in demo; not applied"})

    # ---- graphql (crude, deliberately weak) -----------------------------
    @app.post("/graphql")
    def graphql():
        data = request.get_json(silent=True) or {}
        query = (data.get("query") or "").strip()
        if "__schema" in query or "__type" in query:      # VULN 18: introspection on
            return jsonify({"data": {"__schema": {"queryType": {"name": "Query"},
                            "types": [{"name": "User"}, {"name": "Wallet"},
                                      {"name": "Query"}]}}})
        if "user(" in query:                               # VULN 18: BOLA, no auth
            import re as _re
            m = _re.search(r"user\(\s*id\s*:\s*(\d+)", query)
            if m:
                uid = int(m.group(1))
                for u in users.values():
                    if u["user_id"] == uid:
                        return jsonify({"data": {"user": {
                            "id": uid, "email": u["email"], "balance": u["balance"]}}})
        return jsonify({"data": None})

    # ---- payment webhook (unsigned + replayable) ------------------------
    @app.post("/api/payment/webhook")
    def payment_webhook():
        data = request.get_json(silent=True) or {}
        # VULN 20: no signature verification, no dedupe on order_id.
        order_id = str(data.get("order_id", ""))
        amount = int(data.get("amount", 0))
        uid = data.get("user_id", 1)
        processed_orders.add(order_id)
        for u in users.values():
            if u["user_id"] == uid:
                u["balance"] += amount
                return jsonify({"ok": True, "order_id": order_id, "credited": amount,
                                "balance": u["balance"], "signature_verified": False})
        return jsonify({"error": "user not found"}), 404

    return app


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="GAMEBOX intentionally-vulnerable demo (TEST_COINS)")
    parser.add_argument("--port", type=int, default=5099)
    args = parser.parse_args()
    print("=" * 68)
    print(" GAMEBOX DEMO TARGET - intentionally vulnerable, TEST_COINS only")
    print(" Bound to 127.0.0.1 only. DO NOT expose on a network.")
    print("=" * 68)
    create_app().run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
