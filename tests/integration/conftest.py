"""Shared fixtures for integration tests: locally-served demo targets."""
import threading

import pytest
from werkzeug.serving import make_server

from tests.fixtures.demo_game.app import create_app
from tests.fixtures.demo_game.andar_bahar_ws import create_handler, make_state


@pytest.fixture
def demo_server():
    app = create_app()
    srv = make_server("127.0.0.1", 0, app)  # port 0 => OS picks a free port
    port = srv.server_port
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()


@pytest.fixture
def demo_ws_server():
    from websockets.sync.server import serve as ws_serve
    state = make_state()
    srv = ws_serve(create_handler(state), "127.0.0.1", 0)
    port = srv.socket.getsockname()[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield {"url": f"ws://127.0.0.1:{port}", "state": state}
    finally:
        srv.shutdown()
