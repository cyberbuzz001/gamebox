from gamebox.andarbahar.protocol import ProtocolMapper
from gamebox.andarbahar.analysis import classify_field_trust
from gamebox.andarbahar.ws_client import WSFrame


def _frames():
    return [
        WSFrame("send", "SETTLE", {"round_id": "r1", "winner": "andar", "payout": 100}),
        WSFrame("recv", "ROUND_RESULT", {"round_id": "r1", "winner": "bahar"}),
    ]


def test_protocol_map_marks_sensitivity_and_direction():
    m = ProtocolMapper().build(_frames())
    settle = m["messages"]["SETTLE"]
    assert settle["client_generated"] and not settle["server_generated"]
    assert "winner" in settle["sensitive_fields"] and "payout" in settle["sensitive_fields"]
    assert m["messages"]["ROUND_RESULT"]["server_generated"]


def test_field_trust_classification():
    m = ProtocolMapper().build(_frames())
    cls = classify_field_trust(m)
    assert cls["SETTLE.winner"] == "CLIENT_INPUT"
    assert cls["ROUND_RESULT.winner"] == "SERVER_AUTHORITATIVE"
