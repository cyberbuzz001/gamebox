import os
from gamebox.core.config import Config, _expand_env
from gamebox.core.models import RequestClass


def test_env_expansion():
    os.environ["GAMEBOX_TEST_PW"] = "s3cr3t"
    out = _expand_env({"password": "${GAMEBOX_TEST_PW}"})
    assert out["password"] == "s3cr3t"


def test_allowed_classes_default():
    cfg = Config.from_dict({})
    allowed = cfg.safety.allowed_classes()
    assert RequestClass.READ_ONLY in allowed
    assert RequestClass.SAFE_TEST in allowed
    assert RequestClass.STATE_CHANGING not in allowed
    assert RequestClass.FINANCIAL not in allowed


def test_allowed_classes_opt_in():
    cfg = Config.from_dict({"safety": {"allow_state_changes": True}})
    assert RequestClass.STATE_CHANGING in cfg.safety.allowed_classes()
    assert RequestClass.FINANCIAL not in cfg.safety.allowed_classes()


def test_accounts_parsed():
    cfg = Config.from_dict({"testing": {"accounts": [
        {"label": "A", "username": "u", "password": "p"}]}})
    assert cfg.account("A").username == "u"
    assert cfg.account("missing") is None
