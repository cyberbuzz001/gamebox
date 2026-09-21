"""GAMEBOX demo: an intentionally-vulnerable Andar Bahar WebSocket server.

FOR AUTHORIZED LOCAL TESTING ONLY.
  * Binds to 127.0.0.1 only. Never expose on a network.
  * Synthetic TEST_COINS held in memory. No real money, no persistence.
  * Deliberately vulnerable teaching material for the WebSocket tester.

The server DOES deal a genuine, server-side Andar Bahar round (so the "result"
is server-generated), but SETTLEMENT trusts client-supplied values -- which is
the whole point. Deliberate weaknesses (TEST_COINS only):

  1. Client-controlled result/payout : SETTLE trusts client winner & payout.
  2. Replayable game message          : SETTLE has no msg id/nonce; re-credits.
  3. Missing round binding            : SETTLE takes user_id from the message,
                                        not the authenticated connection.
  4. Duplicate settlement             : the same round settles repeatedly.
  5. Weak WebSocket authorization     : SETTLE works with no prior AUTH; any
                                        token is accepted; no per-message authz.

Protocol (JSON text frames), client -> server types:
  AUTH {token, user_id?}      -> AUTH_OK {user_id, balance}
  JOIN_GAME {}                -> GAME_JOINED {game_id}
  PLACE_BET {round_id, side, amount}
        -> ROUND_CREATED, JOKER_DEALT, ANDAR_CARD*, BAHAR_CARD*, MATCH_FOUND,
           ROUND_RESULT {round_id, winner, matched_card}   (server-authoritative)
  SETTLE {round_id, user_id, winner, payout}  -> SETTLEMENT {...}   (VULNERABLE)
  GET_BALANCE {user_id?}      -> BALANCE {balance}
"""
from __future__ import annotations

import argparse
import json
import random

RANKS = "A23456789TJQK"
SUITS = "SHDC"
DECK = [r + s for r in RANKS for s in SUITS]


def _deal_round(rng: random.Random) -> dict:
    """Deal a genuine Andar Bahar round; the winner is server-generated."""
    deck = DECK[:]
    rng.shuffle(deck)
    joker = deck.pop()
    joker_rank = joker[0]
    andar, bahar = [], []
    winner = None
    side = "andar"
    while deck:
        card = deck.pop()
        (andar if side == "andar" else bahar).append(card)
        if card[0] == joker_rank:
            winner = side
            matched = card
            break
        side = "bahar" if side == "andar" else "andar"
    if winner is None:  # extremely unlikely; default
        winner, matched = "andar", joker
    return {"joker": joker, "andar": andar, "bahar": bahar,
            "winner": winner, "matched_card": matched}


def create_handler(state: dict):
    rng = random.Random(1234)  # deterministic-ish for reproducible demo tests

    def handler(ws):
        conn_user = None  # weak: not required for sensitive actions
        for raw in ws:
            try:
                msg = json.loads(raw)
            except Exception:
                ws.send(json.dumps({"type": "ERROR", "error": "bad json"}))
                continue
            t = msg.get("type")

            if t == "AUTH":
                # VULN 5: any non-empty token accepted; user_id taken from client.
                conn_user = int(msg.get("user_id", 1))
                bal = state["balances"].setdefault(conn_user, 1000)
                ws.send(json.dumps({"type": "AUTH_OK", "user_id": conn_user,
                                    "balance": bal}))

            elif t == "JOIN_GAME":
                ws.send(json.dumps({"type": "GAME_JOINED", "game_id": "ab-table-1"}))

            elif t == "PLACE_BET":
                user = int(msg.get("user_id", conn_user or 1))
                amount = int(msg.get("amount", 0))
                side = msg.get("side", "andar")
                round_id = str(msg.get("round_id", f"r{state['seq']}"))
                state["seq"] += 1
                state["balances"].setdefault(user, 1000)
                state["balances"][user] -= amount
                deal = _deal_round(rng)
                state["rounds"][round_id] = {
                    "user": user, "side": side, "amount": amount,
                    "server_winner": deal["winner"], "settled_count": 0}
                ws.send(json.dumps({"type": "ROUND_CREATED", "round_id": round_id}))
                ws.send(json.dumps({"type": "JOKER_DEALT", "round_id": round_id,
                                    "card": deal["joker"]}))
                for i, c in enumerate(deal["andar"]):
                    ws.send(json.dumps({"type": "ANDAR_CARD", "round_id": round_id, "card": c}))
                for i, c in enumerate(deal["bahar"]):
                    ws.send(json.dumps({"type": "BAHAR_CARD", "round_id": round_id, "card": c}))
                ws.send(json.dumps({"type": "MATCH_FOUND", "round_id": round_id,
                                    "side": deal["winner"], "card": deal["matched_card"]}))
                # ROUND_RESULT is server-authoritative...
                ws.send(json.dumps({"type": "ROUND_RESULT", "round_id": round_id,
                                    "winner": deal["winner"],
                                    "matched_card": deal["matched_card"]}))

            elif t == "SETTLE":
                # VULN 1/2/3/4/5: trusts client winner & payout; user from message;
                # no auth required; no idempotency; duplicates allowed; unknown
                # round accepted.
                user = int(msg.get("user_id", conn_user or 1))
                payout = int(msg.get("payout", 0))
                winner = msg.get("winner")
                round_id = str(msg.get("round_id", ""))
                rnd = state["rounds"].get(round_id)
                if rnd is not None:
                    rnd["settled_count"] += 1
                state["balances"].setdefault(user, 1000)
                state["balances"][user] += payout          # client-controlled payout
                ws.send(json.dumps({"type": "SETTLEMENT", "round_id": round_id,
                                    "user_id": user, "winner": winner,
                                    "credited": payout,
                                    "balance": state["balances"][user],
                                    "server_verified": False}))

            elif t == "GET_BALANCE":
                user = int(msg.get("user_id", conn_user or 1))
                bal = state["balances"].setdefault(user, 1000)
                ws.send(json.dumps({"type": "BALANCE", "user_id": user, "balance": bal}))

            else:
                ws.send(json.dumps({"type": "ERROR", "error": f"unknown type {t}"}))

    return handler


def make_state() -> dict:
    return {"balances": {1: 1000, 2: 1000}, "rounds": {}, "seq": 1}


def serve(host: str = "127.0.0.1", port: int = 8765):
    from websockets.sync.server import serve as ws_serve
    state = make_state()
    return ws_serve(create_handler(state), host, port), state


def main() -> None:
    parser = argparse.ArgumentParser(
        description="GAMEBOX vulnerable Andar Bahar WS demo (TEST_COINS)")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    print("=" * 68)
    print(" GAMEBOX ANDAR BAHAR WS DEMO - intentionally vulnerable, TEST_COINS")
    print(" Bound to 127.0.0.1 only. DO NOT expose on a network.")
    print("=" * 68)
    server, _ = serve("127.0.0.1", args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
