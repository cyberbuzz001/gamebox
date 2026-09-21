"""Payment integration security checks.

Tests a payment webhook/callback for signature verification and replay
protection. These are FINANCIAL-class requests: they are blocked by the safety
controller unless the operator has explicitly enabled financial operations for
an authorized sandbox that uses synthetic currency. Amounts are tiny and
synthetic; no real payment is ever initiated.
"""
from __future__ import annotations

from typing import Optional

from ..analyzers.common import AccountSession
from ..core.logger import get_logger
from ..core.models import Category, Confidence, Finding, Severity
from ..http.client import BlockedRequest, SafeHTTPClient

log = get_logger("payments")

_PROBE_AMOUNT = 5  # synthetic TEST_COINS


class PaymentAnalyzer:
    def __init__(self, client: SafeHTTPClient, base_url: str,
                 webhook_path: str = "/api/payment/webhook",
                 balance_path: str = "/api/wallet/me"):
        self.client = client
        self.base = base_url.rstrip("/")
        self.webhook_path = webhook_path
        self.balance_path = balance_path

    def _balance(self, sess: AccountSession) -> Optional[float]:
        try:
            resp, _ = self.client.get(self.base + self.balance_path, headers=sess.headers())
        except Exception:
            return None
        body = resp.json() or {}
        v = body.get("balance")
        return float(v) if v is not None else None

    def run(self, sess: AccountSession) -> list[Finding]:
        if sess.user_id is None:
            return []
        b0 = self._balance(sess)
        if b0 is None:
            return []
        url = self.base + self.webhook_path
        order_id = "gbx-pay-probe-1"
        payload = {"order_id": order_id, "amount": _PROBE_AMOUNT,
                   "user_id": sess.user_id}  # note: NO signature field
        try:
            r1, ev1 = self.client.post(url, json_body=payload)
            b1 = self._balance(sess)
            r2, ev2 = self.client.post(url, json_body=payload)  # replay same order_id
            b2 = self._balance(sess)
        except BlockedRequest as b:
            log.info("payment webhook test skipped (blocked): %s -- enable "
                     "allow_financial_operations for an authorized sandbox to run it.",
                     b.decision.reason)
            return []
        except Exception:
            return []
        if b1 is None or b2 is None:
            return []

        out: list[Finding] = []
        body1 = r1.json() or {}
        if (b1 - b0) > 0 and r1.status_code < 400 and body1.get("signature_verified") is not True:
            if ev1:
                ev1.test_account = sess.label
            out.append(Finding(
                title="Payment webhook accepts unsigned/forgeable callbacks",
                category=Category.PAYMENT, severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
                description="The payment webhook credited the wallet from a callback that "
                "carried no valid signature; the server did not verify authenticity.",
                endpoint=f"POST {self.webhook_path}", parameter="signature/amount/user_id",
                impact="An attacker can forge payment-success callbacks and credit arbitrary "
                "amounts to arbitrary users (demonstrated on TEST_COINS).",
                reproduction=f"POST {self.webhook_path} with no signature and a chosen amount; "
                "the wallet is credited.",
                remediation="Verify a provider HMAC/signature on every callback; validate "
                "amount/currency/order against the originating charge; reject unsigned calls.",
                cwe="CWE-345 (Insufficient Verification of Data Authenticity)",
                owasp="API8:2023 / payment integrity", module="payments",
                evidence=[ev1] if ev1 else []))

        if (b2 - b1) > 0 and r2.status_code < 400:
            if ev2:
                ev2.test_account = sess.label
            out.append(Finding(
                title="Payment webhook is replayable (duplicate callback double-credits)",
                category=Category.PAYMENT, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                description="Re-sending the same callback (identical order_id) credited the "
                "wallet again; there is no idempotency/dedupe on the order id.",
                endpoint=f"POST {self.webhook_path}", parameter="order_id",
                impact="A captured callback can be replayed to inflate balances repeatedly.",
                reproduction=f"POST {self.webhook_path} twice with the same order_id; both "
                "credit.",
                remediation="Deduplicate on a unique provider event/order id inside a "
                "transaction; make crediting idempotent.",
                cwe="CWE-837 (Improper Enforcement of a Single, Unique Action)",
                owasp="API6:2023 / payment integrity", module="payments",
                evidence=[ev2] if ev2 else []))
        return out
