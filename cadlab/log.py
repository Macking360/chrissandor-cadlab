from __future__ import annotations

import hashlib
import json
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from .platform_support import Layout, current_layout, iso, secure_file, utcnow

GENESIS = "0" * 64


def _digest(previous: str, body: str) -> str:
    return hashlib.sha256((previous + body).encode("utf-8")).hexdigest()


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, default=str, separators=(",", ":"))


class AuditTrail:
    def __init__(self, path: Path):
        self.path = Path(path)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        size = self.path.stat().st_size
        if size == 0:
            return GENESIS
        with self.path.open("rb") as stream:
            stream.seek(max(0, size - 65536))
            tail = stream.read()
        lines = [line for line in tail.splitlines() if line.strip()]
        if not lines:
            return GENESIS
        try:
            return json.loads(lines[-1].decode("utf-8"))["hash"]
        except (ValueError, KeyError):
            raise ValueError("The audit trail tail is unreadable; run 'cadlab pki audit-verify'.")

    def append(self, action: str, **details) -> dict:
        previous = self._last_hash()
        record = {"timestamp": iso(utcnow()), "action": action, **details, "prev": previous}
        record["hash"] = _digest(previous, _canonical(record))
        line = _canonical(record) + "\n"
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
        secure_file(self.path)
        return record

    def verify(self) -> dict:
        if not self.path.exists():
            return {"ok": True, "records": 0, "head": GENESIS, "problem": None}
        previous, count = GENESIS, 0
        with self.path.open("r", encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    return {"ok": False, "records": count, "head": previous, "problem": f"line {number} is not valid JSON"}
                claimed = record.pop("hash", None)
                if record.get("prev") != previous:
                    return {"ok": False, "records": count, "head": previous, "problem": f"line {number} does not follow the previous record"}
                if claimed != _digest(previous, _canonical(record)):
                    return {"ok": False, "records": count, "head": previous, "problem": f"line {number} was altered"}
                previous, count = claimed, count + 1
        return {"ok": True, "records": count, "head": previous, "problem": None}


class AppLog:
    logger = logging.getLogger("cadlab")
    audit: Optional[AuditTrail] = None
    _bound: Optional[Path] = None

    @classmethod
    def setup(cls, layout: Optional[Layout] = None) -> None:
        layout = layout or current_layout()
        if cls._bound == layout.log_path and cls.logger.handlers and cls.audit is not None:
            return
        for handler in list(cls.logger.handlers):
            handler.close()
            cls.logger.removeHandler(handler)
        layout.dirs["logs"].mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(layout.log_path, maxBytes=2_000_000, backupCount=8, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        cls.logger.addHandler(handler)
        cls.logger.setLevel(logging.INFO)
        cls.logger.propagate = False
        cls.audit = AuditTrail(layout.audit_path)
        cls._bound = layout.log_path

    @classmethod
    def event(cls, action: str, **details) -> None:
        if cls.audit is None or cls._bound != current_layout().log_path:
            cls.setup()
        cls.audit.append(action, **details)
        cls.logger.info("event: %s", action)
