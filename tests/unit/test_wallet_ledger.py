from gamebox.analyzers.wallet import Ledger


def test_expected_balance():
    l = Ledger(1000)
    l.credit(100)
    l.debit(30)
    assert l.expected == 1070


def test_duplicate_credit_detectable_via_ledger():
    # One legitimate claim credits 100; a second must NOT be expected.
    l = Ledger(500)
    l.credit(100)
    assert l.expected == 600  # observed 700 after a replay => integrity gap
