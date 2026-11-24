"""Pure-Python local HTTP server for FireGuard Web UI."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from typing import Any, Optional
from urllib.parse import urlparse
import uuid

from fireguard.audit import AuditLogger
from fireguard.backends.registry import get_backend, list_backends
from fireguard.engine import (
    PacketQuery,
    evaluate_packet,
    inspect_effective_policy,
    starter_policies,
)
from fireguard.models import (
    Action,
    Direction,
    IPVersion,
    Policy,
    PortRange,
    Protocol,
    Rule,
    Schedule,
    SystemDefaults,
    explain_rule,
)
from fireguard.storage import PolicyImportError, PolicyStore, parse_and_validate_import
from fireguard.validation import validate_policy

STATIC_DIR = Path(__file__).parent / "static"


class _PendingConfirmation:
    def __init__(self, token: str, backend_name: str, snapshot_path: Path, timeout: int) -> None:
        self.token = token
        self.backend_name = backend_name
        self.snapshot_path = snapshot_path
        self.timeout = timeout
        self.confirmed = False
        self.timer: Optional[threading.Timer] = None


class FireGuardAppState:
    """Shared state for the local Web UI server."""

    def __init__(self, data_dir: Optional[Path] = None) -> None:
        self.store = PolicyStore(data_dir)
        self.audit = AuditLogger(data_dir)
        self.lock = threading.Lock()
        self.pending: dict[str, _PendingConfirmation] = {}

    def schedule_rollback(
        self, backend_name: str, snapshot_path: Path, timeout: int
    ) -> str:
        token = str(uuid.uuid4())[:12]
        entry = _PendingConfirmation(token, backend_name, snapshot_path, timeout)

        def _on_timeout() -> None:
            with self.lock:
                cur = self.pending.pop(token, None)
            if cur and not cur.confirmed:
                backend = get_backend(cur.backend_name)
                snap = self.store.load_snapshot(cur.snapshot_path)
                ok, msg = backend.rollback(snap)
                self.audit.log(
                    "policy.auto_rollback",
                    outcome="success" if ok else "failed",
                    details={"backend": cur.backend_name, "message": msg},
                )

        timer = threading.Timer(timeout, _on_timeout)
        timer.daemon = True
        entry.timer = timer
        with self.lock:
            self.pending[token] = entry
        timer.start()
        return token

    def confirm_token(self, token: str) -> bool:
        with self.lock:
            entry = self.pending.pop(token, None)
        if not entry:
            return False
        entry.confirmed = True
        if entry.timer:
            entry.timer.cancel()
        self.audit.log("policy.confirm", details={"backend": entry.backend_name})
        return True


def make_handler(state: FireGuardAppState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return  # Keep console clean; structured events go to AuditLogger

        def _send_json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_static(self, filename: str, content_type: str) -> None:
            target = (STATIC_DIR / filename).resolve()
            if not target.is_file() or STATIC_DIR.resolve() not in target.parents:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            data = target.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            return json.loads(raw)

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/" or path == "/index.html":
                self._send_static("index.html", "text/html; charset=utf-8")
                return
            if path == "/styles.css":
                self._send_static("styles.css", "text/css; charset=utf-8")
                return
            if path == "/app.js":
                self._send_static("app.js", "application/javascript; charset=utf-8")
                return

            if path == "/api/policy":
                pol = state.store.load()
                val = validate_policy(pol)
                self._send_json(
                    200,
                    {
                        "policy": pol.to_dict(),
                        "validation": val.to_dict(),
                        "explanations": {r.id: explain_rule(r) for r in pol.rules},
                        "inspection": inspect_effective_policy(pol),
                    },
                )
                return

            if path == "/api/backends":
                backends = []
                for b in list_backends():
                    avail, reason = b.check_availability()
                    backends.append(
                        {
                            "name": b.name,
                            "platform_name": b.platform_name,
                            "available": avail,
                            "availability_reason": reason,
                            "elevated": b.is_elevated(),
                            "capabilities": b.capabilities().to_dict(),
                        }
                    )
                self._send_json(200, {"backends": backends})
                return

            if path == "/api/starters":
                self._send_json(
                    200,
                    {
                        "starters": {
                            k: {"description": v.description, "rule_count": len(v.rules)}
                            for k, v in starter_policies().items()
                        }
                    },
                )
                return

            if path == "/api/audit":
                self._send_json(200, {"entries": state.audit.read_recent(50)})
                return

            self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            try:
                body = self._read_json()
            except json.JSONDecodeError as exc:
                self._send_json(400, {"error": f"Invalid JSON: {exc}"})
                return

            if path == "/api/rules":
                pol = state.store.load()
                try:
                    rule = Rule.from_dict(body)
                except (ValueError, TypeError) as exc:
                    self._send_json(400, {"error": str(exc)})
                    return
                pol.rules.append(rule)
                val = validate_policy(pol)
                if not val.is_valid:
                    self._send_json(400, {"error": "Validation failed", "validation": val.to_dict()})
                    return
                state.store.save(pol)
                state.audit.log("rule.add", details={"rule_id": rule.id, "name": rule.name})
                self._send_json(200, {"rule": rule.to_dict(), "validation": val.to_dict()})
                return

            if path == "/api/rules/toggle":
                pol = state.store.load()
                rid = body.get("id")
                target = next((r for r in pol.rules if r.id == rid), None)
                if not target:
                    self._send_json(404, {"error": "Rule not found"})
                    return
                target.enabled = not target.enabled
                state.store.save(pol)
                state.audit.log("rule.toggle", details={"rule_id": rid, "enabled": target.enabled})
                self._send_json(200, {"rule": target.to_dict()})
                return

            if path == "/api/rules/move":
                pol = state.store.load()
                rid = body.get("id")
                delta = int(body.get("delta", 0))
                idx = next((i for i, r in enumerate(pol.rules) if r.id == rid), None)
                if idx is None:
                    self._send_json(404, {"error": "Rule not found"})
                    return
                new_idx = max(0, min(len(pol.rules) - 1, idx + delta))
                item = pol.rules.pop(idx)
                pol.rules.insert(new_idx, item)
                state.store.save(pol)
                state.audit.log("rule.move", details={"rule_id": rid, "position": new_idx + 1})
                self._send_json(200, {"ok": True})
                return

            if path == "/api/rules/delete":
                pol = state.store.load()
                rid = body.get("id")
                pol.rules = [r for r in pol.rules if r.id != rid]
                state.store.save(pol)
                state.audit.log("rule.remove", details={"rule_id": rid})
                self._send_json(200, {"ok": True})
                return

            if path == "/api/defaults":
                pol = state.store.load()
                try:
                    pol.defaults = SystemDefaults.from_dict(body)
                except (ValueError, TypeError) as exc:
                    self._send_json(400, {"error": str(exc)})
                    return
                val = validate_policy(pol)
                if not val.is_valid:
                    self._send_json(400, {"error": "Invalid defaults", "validation": val.to_dict()})
                    return
                state.store.save(pol)
                state.audit.log("policy.defaults_updated")
                self._send_json(200, {"ok": True, "validation": val.to_dict()})
                return

            if path == "/api/starters/load":
                name = body.get("name", "")
                starters = starter_policies()
                if name not in starters:
                    self._send_json(404, {"error": "Starter policy not found"})
                    return
                state.store.save(starters[name])
                state.audit.log("policy.load_starter", details={"starter": name})
                self._send_json(200, {"ok": True})
                return

            if path == "/api/import":
                raw = body.get("raw_json", "")
                try:
                    imported, val = parse_and_validate_import(raw)
                except PolicyImportError as exc:
                    self._send_json(400, {"error": str(exc), "details": exc.details})
                    return
                state.store.save(imported)
                state.audit.log("policy.import", details={"rules": len(imported.rules)})
                self._send_json(200, {"ok": True, "validation": val.to_dict()})
                return

            if path == "/api/simulate":
                pol = state.store.load()
                try:
                    query = PacketQuery(
                        direction=Direction(body["direction"]),
                        source_ip=body["source_ip"],
                        dest_ip=body["dest_ip"],
                        protocol=Protocol(body.get("protocol", "tcp")),
                        source_port=int(body["source_port"]) if body.get("source_port") else None,
                        dest_port=int(body["dest_port"]) if body.get("dest_port") else None,
                        interface=body.get("interface") or None,
                        application=body.get("application") or None,
                        established=bool(body.get("established", False)),
                    )
                    res = evaluate_packet(pol, query)
                except (ValueError, KeyError) as exc:
                    self._send_json(400, {"error": str(exc)})
                    return
                self._send_json(200, res.to_dict())
                return

            if path == "/api/preview":
                pol = state.store.load()
                backend_name = body.get("backend", "auto")
                backend = get_backend(backend_name)
                prev = backend.render_preview(pol)
                state.audit.log("policy.preview", details={"backend": backend.name})
                self._send_json(200, prev.to_dict())
                return

            if path == "/api/apply":
                pol = state.store.load()
                backend_name = body.get("backend", "auto")
                dry_run = bool(body.get("dry_run", True))
                confirmed = bool(body.get("confirmed", False))
                backend = get_backend(backend_name)
                if dry_run or not confirmed:
                    prev = backend.render_preview(pol)
                    self._send_json(
                        200,
                        {
                            "dry_run": True,
                            "message": "Dry-run preview only. Explicit confirmation required for live apply.",
                            "preview": prev.to_dict(),
                        },
                    )
                    return

                res = backend.apply_live(pol, state.store, confirm_callback=None, previous_policy=pol)
                state.audit.log(
                    "policy.apply",
                    outcome="success" if res.success else "failed",
                    details={"backend": backend.name},
                )
                payload = res.to_dict()
                if res.success and res.snapshot_path:
                    token = state.schedule_rollback(
                        backend.name,
                        Path(res.snapshot_path),
                        pol.defaults.rollback_timeout_seconds,
                    )
                    payload["confirm_token"] = token
                    payload["rollback_timeout_seconds"] = pol.defaults.rollback_timeout_seconds
                self._send_json(200 if res.success else 400, payload)
                return

            if path == "/api/confirm":
                token = body.get("token", "")
                ok = state.confirm_token(token)
                self._send_json(200 if ok else 404, {"confirmed": ok})
                return

            if path == "/api/rollback":
                backend = get_backend(body.get("backend", "auto"))
                try:
                    snap = state.store.load_snapshot()
                except FileNotFoundError as exc:
                    self._send_json(404, {"error": str(exc)})
                    return
                ok, msg = backend.rollback(snap)
                state.audit.log("policy.rollback", outcome="success" if ok else "failed")
                self._send_json(200 if ok else 400, {"success": ok, "message": msg})
                return

            self._send_json(404, {"error": "Not found"})

    return Handler


def run_server(host: str = "127.0.0.1", port: int = 8420, data_dir: Optional[Path] = None) -> None:
    state = FireGuardAppState(data_dir)
    server = ThreadingHTTPServer((host, port), make_handler(state))
    print(f"FireGuard Web UI running at http://{host}:{port} (dry-run by default)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down FireGuard Web UI.")
        server.server_close()
