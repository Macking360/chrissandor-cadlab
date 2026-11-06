import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from cadlab import overwatch_link as link


class FakeOverWatch(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *args):
        pass

    def _reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length) or b"{}")
        FakeOverWatch.seen.append((self.path, dict(self.headers), payload))
        if self.path == "/api/enroll":
            if self.headers.get("X-Enroll-Key") != "right-key":
                return self._reply(401, {"error": "bad key"})
            return self._reply(201, {"token": "device-token-1"})
        if self.path == "/api/events":
            if self.headers.get("Authorization") != "Bearer device-token-1":
                return self._reply(401, {"error": "invalid or revoked device token"})
            return self._reply(202, {"stored": len(payload.get("events", []))})
        self._reply(404, {})


@pytest.fixture
def fake_server():
    FakeOverWatch.seen = []
    server = HTTPServer(("127.0.0.1", 0), FakeOverWatch)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def url(server, scheme="http"):
    return f"{scheme}://127.0.0.1:{server.server_address[1]}"


def test_enroll_and_send_follow_the_overwatch_contract(fake_server):
    token = link.enroll(url(fake_server), "right-key", "unit-device")
    assert token == "device-token-1"
    path, headers, body = FakeOverWatch.seen[0]
    assert path == "/api/enroll" and set(body) == {"name", "platform", "fingerprint"} and body["name"] == "unit-device"
    stored = link.send_events(url(fake_server), token, [{"monitor": "cadlab", "target": "t", "action": "a",
                                                          "severity": "info", "detail": "d"}])
    assert stored == 1
    path, headers, body = FakeOverWatch.seen[1]
    assert path == "/api/events" and headers["Authorization"] == "Bearer device-token-1"
    assert body["events"][0]["monitor"] == "cadlab"


def test_wrong_enroll_key_and_bad_token_are_clear_errors(fake_server):
    with pytest.raises(link.LinkError, match="401"):
        link.enroll(url(fake_server), "wrong", "x")
    with pytest.raises(link.LinkError, match="401"):
        link.send_events(url(fake_server), "nope", [])


def test_unreachable_server_and_bad_scheme():
    with pytest.raises(link.LinkError, match="Could not reach"):
        link.send_events("http://127.0.0.1:1", "t", [], )
    with pytest.raises(link.LinkError, match="http"):
        link.send_events("ftp://example", "t", [])


def test_link_is_saved_with_owner_only_token(layout):
    link.save_link(layout, "https://ow.example:8771/", "secret-token", "ca.pem")
    loaded = link.load_link(layout)
    assert loaded == {"server": "https://ow.example:8771", "ca_cert": "ca.pem", "token": "secret-token"}
    assert "secret-token" not in layout.config_path.read_text(encoding="utf-8")
    import os
    if os.name != "nt":
        assert (layout.dirs["config"] / link.TOKEN_FILE).stat().st_mode & 0o077 == 0


def test_seal_event_severity_mapping():
    clean = {"ok": True, "state": "intact", "files": {"modified": [], "added": [], "missing": []},
             "signer": "CN=x", "problems": []}
    tampered = dict(clean, ok=False, state="modified", files={"modified": ["a"], "added": [], "missing": []})
    assert link.seal_event(clean, "/p")["severity"] == "info"
    event = link.seal_event(tampered, "/p")
    assert event["severity"] == "critical" and event["action"] == "seal_violation"
    assert json.loads(event["detail"])["modified"] == ["a"]
    assert link.SEVERITY.keys() >= {"intact", "modified", "invalid-signature", "untrusted-signer"}


def test_agent_command_quotes_paths_with_spaces():
    text = link.agent_command("/my projects/demo", "https://h:8771", "dev", "/ca.pem")
    assert '"/my projects/demo"' in text and "--ca-cert /ca.pem" in text and "--watch-file" in text


def test_https_link_works_with_a_certificate_we_issued(lab, tmp_path, fake_server):
    server_cert = lab.issue("server", "localhost", sans=["localhost", "127.0.0.1"])
    from cadlab.keys import read_private_key
    from cryptography.hazmat.primitives import serialization
    key = read_private_key(Path(server_cert["key_path"]))
    key_file = tmp_path / "plain-key.pem"
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(server_cert["chain_path"], str(key_file))
    fake_server.socket = context.wrap_socket(fake_server.socket, server_side=True)
    root = str(lab.ca_paths("root")[0])
    address = url(fake_server, "https")
    assert link.enroll(address, "right-key", "tls-device", ca_cert=root) == "device-token-1"
    with pytest.raises(link.LinkError, match="Could not reach"):
        link.enroll(address, "right-key", "tls-device")
