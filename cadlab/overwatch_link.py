from __future__ import annotations

import json
import platform
import socket
import ssl
import urllib.error
import urllib.request
from typing import List, Optional

from .platform_support import Layout, atomic_write, current_layout, load_config, save_config

TOKEN_FILE = "overwatch-token"
SEVERITY = {"intact": "info", "unsealed": "notice", "modified": "critical", "invalid-signature": "critical",
            "untrusted-signer": "critical", "damaged-seal": "critical"}


class LinkError(RuntimeError):
    pass


def _context(url: str, ca_cert: str = "", client_cert: str = "", client_key: str = ""):
    if not url.lower().startswith("https://"):
        return None
    context = ssl.create_default_context(cafile=ca_cert or None)
    if client_cert:
        context.load_cert_chain(client_cert, client_key or None)
    return context


def _request(url: str, payload: Optional[dict], headers: dict, ca_cert: str = "", client_cert: str = "",
             client_key: str = "", timeout: float = 10.0):
    if not url.lower().startswith(("http://", "https://")):
        raise LinkError("The OverWatch address must start with http:// or https://")
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET",
                                     headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=_context(url, ca_cert, client_cert, client_key)) as reply:
            return reply.status, json.loads(reply.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as error:
        raise LinkError(f"OverWatch answered {error.code}: {error.read().decode('utf-8', 'replace')[:200]}") from error
    except (urllib.error.URLError, ssl.SSLError, OSError) as error:
        reason = getattr(error, "reason", error)
        raise LinkError(f"Could not reach OverWatch: {reason}") from error


def enroll(server: str, enroll_key: str, name: str = "", ca_cert: str = "", client_cert: str = "",
           client_key: str = "") -> str:
    name = name or ("cadlab-" + (socket.gethostname() or "device"))
    status, body = _request(server.rstrip("/") + "/api/enroll",
                            {"name": name, "platform": platform.platform(), "fingerprint": {}},
                            {"X-Enroll-Key": enroll_key}, ca_cert, client_cert, client_key)
    token = body.get("token")
    if status != 201 or not token:
        raise LinkError("Enrollment did not return a device token.")
    return token


def save_link(layout: Layout, server: str, token: str, ca_cert: str = "") -> None:
    config = load_config(layout)
    config["overwatch"] = {"server": server.rstrip("/"), "ca_cert": ca_cert}
    save_config(layout, config)
    atomic_write(layout.dirs["config"] / TOKEN_FILE, token.encode("utf-8"), 0o600)


def load_link(layout: Optional[Layout] = None) -> dict:
    layout = layout or current_layout()
    config = load_config(layout)["overwatch"]
    token_path = layout.dirs["config"] / TOKEN_FILE
    token = token_path.read_text(encoding="utf-8").strip() if token_path.exists() else ""
    return {"server": config.get("server", ""), "ca_cert": config.get("ca_cert", ""), "token": token}


def send_events(server: str, token: str, events: List[dict], ca_cert: str = "", client_cert: str = "",
                client_key: str = "") -> int:
    status, body = _request(server.rstrip("/") + "/api/events", {"events": events},
                            {"Authorization": f"Bearer {token}"}, ca_cert, client_cert, client_key)
    if status not in (200, 202):
        raise LinkError(f"Unexpected reply {status} from OverWatch.")
    return int(body.get("stored", 0))


def seal_event(report: dict, project_path: str) -> dict:
    files = report["files"]
    detail = {"state": report["state"], "modified": files["modified"][:20], "added": files["added"][:20],
              "missing": files["missing"][:20], "signer": report.get("signer"), "problems": report["problems"][:5]}
    action = "seal_verified" if report["ok"] else "seal_violation"
    return {"monitor": "cadlab", "target": project_path, "action": action,
            "severity": SEVERITY.get(report["state"], "warning") if not report["ok"] else "info",
            "detail": json.dumps(detail, sort_keys=True)[:2000]}


def agent_command(project_path: str, server: str = "https://HOST:8771", name: str = "cadlab-device",
                  ca_cert: str = "") -> str:
    parts = ["python", "-m", "overwatch", "agent", "--server", server, "--enroll-key", "<enroll key>",
             "--name", name, "--watch-file", project_path]
    if ca_cert:
        parts += ["--ca-cert", ca_cert]
    return " ".join(f'"{p}"' if " " in p else p for p in parts)
