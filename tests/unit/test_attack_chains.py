from gamebox.core.models import Category, Confidence, Finding, Severity
from gamebox.reporting import attack_chains


def _f(title, module, category=Category.OTHER, sev=Severity.HIGH):
    return Finding(title=title, category=category, severity=sev,
                   confidence=Confidence.CONFIRMED, description="d", module=module)


def test_balance_inflation_chain():
    fs = [_f("Game payout is client-controlled", "games", Category.GAME),
          _f("Replayable bonus claim leads to duplicate TEST_COINS credit", "wallet",
             Category.BONUS)]
    chains = attack_chains.correlate(fs)
    assert any(c.name == "Unauthorized balance inflation" for c in chains)


def test_account_takeover_chain_from_reset():
    fs = [_f("Insecure password reset: token returned in response", "authentication",
             Category.AUTH)]
    chains = attack_chains.correlate(fs)
    assert any(c.name == "Account takeover path" for c in chains)


def test_no_chain_without_components():
    fs = [_f("Missing security response headers", "api")]
    chains = attack_chains.correlate(fs)
    assert all(c.name != "Unauthorized balance inflation" for c in chains)
