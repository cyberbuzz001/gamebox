from gamebox.andarbahar.environment import Environment, EnvironmentPolicy


def test_demo_allows_mutation():
    p = EnvironmentPolicy.from_name("demo")
    assert p.allow_mutation and not p.safe_read_only


def test_staging_allows_mutation():
    assert EnvironmentPolicy.from_name("staging").allow_mutation


def test_production_is_read_only():
    p = EnvironmentPolicy.from_name("production")
    assert not p.allow_mutation
    assert p.safe_read_only
    assert not p.allow_financial_mutation


def test_unknown_defaults_to_demo():
    assert EnvironmentPolicy.from_name("weird").environment == Environment.DEMO
    assert EnvironmentPolicy.from_name(None).environment == Environment.DEMO
