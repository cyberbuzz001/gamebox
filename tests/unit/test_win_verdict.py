from gamebox.games.win_integrity import (
    _worst, SECURE, POTENTIAL, CONF_OUTCOME, CONF_SETTLE, CONF_REPLAY, CONF_RACE)


def test_worst_priority():
    assert _worst([CONF_RACE, CONF_SETTLE, POTENTIAL]) == CONF_SETTLE
    assert _worst([CONF_REPLAY, CONF_RACE]) == CONF_REPLAY
    assert _worst([POTENTIAL, SECURE]) == POTENTIAL
    assert _worst([]) == SECURE


def test_settlement_beats_outcome():
    assert _worst([CONF_OUTCOME, CONF_SETTLE]) == CONF_SETTLE
