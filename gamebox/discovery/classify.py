"""Categorize an endpoint URL into a functional Category (application map)."""
from __future__ import annotations

from ..core.models import Category

# Checked in order; first match wins. Most specific categories first.
_RULES: list[tuple[Category, tuple[str, ...]]] = [
    (Category.WITHDRAWAL, ("withdraw", "cashout", "cash-out", "payout")),
    (Category.DEPOSIT, ("deposit", "topup", "top-up", "recharge", "addfunds")),
    (Category.PAYMENT, ("payment", "pay/", "/pay", "checkout", "callback", "webhook", "upi", "gateway")),
    (Category.WALLET, ("wallet", "balance", "coins", "credit", "ledger")),
    (Category.BONUS, ("bonus", "reward", "cashback", "promo", "promotion", "claim")),
    (Category.REFERRAL, ("referral", "refer", "invite")),
    (Category.BETTING, ("bet", "stake", "wager", "odds")),
    (Category.GAME, ("game", "round", "settle", "settlement", "spin", "cards", "dice",
                     "roulette", "teenpatti", "rummy", "poker", "crash", "slot", "jackpot")),
    (Category.AUTH, ("login", "logout", "signin", "sign-in", "auth", "token", "otp",
                     "password", "register", "signup", "sign-up")),
    (Category.ADMIN, ("admin", "staff", "manage", "backoffice", "console", "dashboard/admin")),
    (Category.SUPPORT, ("support", "ticket", "help", "complaint")),
    (Category.NOTIFICATION, ("notification", "notify", "message", "inbox")),
    (Category.REPORTING, ("report", "stats", "statement", "history")),
    (Category.PROFILE, ("profile", "account/me", "kyc", "settings")),
    (Category.USER, ("user", "users", "player", "customer")),
]


def categorize(url: str) -> Category:
    low = url.lower()
    for cat, kws in _RULES:
        if any(k in low for k in kws):
            return cat
    return Category.OTHER
