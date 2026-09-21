import pytest
from gamebox.andarbahar.environment import EnvironmentPolicy, MutationBlocked
from gamebox.andarbahar.ws_client import SafeWebSocketClient
from gamebox.core.config import Config
from gamebox.safety.controller import SafetyController


class _DummyWS:
    def send(self, data): self.sent = data


def _client(env):
    cfg = Config.from_dict({"scope": {"domains": ["127.0.0.1"], "api_hosts": ["127.0.0.1"]},
                            "safety": {"allow_state_changes": True}})
    c = SafeWebSocketClient("ws://127.0.0.1:9/x", SafetyController(cfg),
                            EnvironmentPolicy.from_name(env))
    c._ws = _DummyWS()
    return c


def test_production_refuses_mutation():
    c = _client("production")
    with pytest.raises(MutationBlocked):
        c.send({"type": "SETTLE", "round_id": "r", "payout": 100}, mutation=True)


def test_demo_allows_mutation_send():
    c = _client("demo")
    c.send({"type": "SETTLE", "round_id": "r", "payout": 100}, mutation=True)
    assert getattr(c._ws, "sent", None) is not None
