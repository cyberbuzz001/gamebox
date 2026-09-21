from gamebox.core.models import Category, Endpoint
from gamebox.games.discovery import GameDiscovery


def test_profiles_and_risk_indicators():
    eps = [
        Endpoint(method="POST", url="https://api.test/api/game/teenpatti/bet",
                 parameters=["bet_amount", "payout"], category=Category.BETTING),
        Endpoint(method="POST", url="https://api.test/api/game/settlement",
                 parameters=["round_id"], category=Category.GAME),
    ]
    profiles = GameDiscovery().analyze(eps)
    assert profiles
    names = {p.name for p in profiles}
    assert "teenpatti" in names or "game" in names
    all_ind = " ".join(i for p in profiles for i in p.risk_indicators)
    assert "payout" in all_ind
    assert "settlement" in all_ind
