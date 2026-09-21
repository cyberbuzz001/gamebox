from gamebox.core.models import (
    Category, Confidence, Endpoint, Finding, Severity, severity_rank,
)


def test_severity_order():
    assert severity_rank(Severity.CRITICAL) < severity_rank(Severity.HIGH)
    assert severity_rank(Severity.LOW) < severity_rank(Severity.INFO)


def test_endpoint_to_dict():
    ep = Endpoint(method="get", url="https://api.test/x", category=Category.WALLET)
    d = ep.to_dict()
    assert d["category"] == "WALLET"
    assert ep.key() == "GET https://api.test/x"


def test_finding_to_dict():
    f = Finding(title="t", category=Category.GAME, severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED, description="d")
    d = f.to_dict()
    assert d["severity"] == "HIGH"
    assert d["confidence"] == "CONFIRMED"
    assert d["category"] == "GAME"
