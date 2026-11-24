"""Command-line interface for FireGuard."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import select
import sys
from typing import Optional

from fireguard.audit import AuditLogger
from fireguard.backends.registry import get_backend
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
    explain_rule,
)
from fireguard.storage import PolicyImportError, PolicyStore, parse_and_validate_import
from fireguard.validation import validate_policy


def _interactive_connectivity_confirm(timeout_seconds: int) -> bool:
    """Wait up to timeout_seconds for user to type 'confirm' on stdin."""
    print(
        f"\n[ROLLBACK GUARD] Rules applied. Type 'confirm' within {timeout_seconds}s "
        "to keep changes, or press Enter/wait to roll back: ",
        end="",
        flush=True,
    )
    if not sys.stdin.isatty():
        return False
    ready, _, _ = select.select([sys.stdin], [], [], timeout_seconds)
    if not ready:
        print("\nTimeout reached without confirmation.")
        return False
    line = sys.stdin.readline().strip().lower()
    return line in ("confirm", "yes", "y", "ok")


def _cmd_policy(args: argparse.Namespace, store: PolicyStore, audit: AuditLogger) -> int:
    if args.policy_cmd == "init":
        if store.exists() and not args.force:
            print(f"Policy already exists at {store.policy_path}. Use --force to overwrite.")
            return 1
        policy = Policy()
        store.save(policy)
        audit.log("policy.init", details={"path": str(store.policy_path)})
        print(f"Initialized default policy at {store.policy_path} (dry-run only; not applied).")
        return 0

    if args.policy_cmd == "starters":
        for name, pol in starter_policies().items():
            print(f"- {name}: {pol.description} ({len(pol.rules)} rules)")
        return 0

    if args.policy_cmd == "load-starter":
        starters = starter_policies()
        if args.name not in starters:
            print(f"Unknown starter '{args.name}'. Available: {sorted(starters.keys())}")
            return 1
        store.save(starters[args.name])
        audit.log("policy.load_starter", details={"starter": args.name})
        print(f"Loaded starter '{args.name}' into {store.policy_path} (not applied to live system).")
        return 0

    policy = store.load()

    if args.policy_cmd == "show":
        print(store.export_json(policy))
        return 0

    if args.policy_cmd == "validate":
        res = validate_policy(policy)
        print(json.dumps(res.to_dict(), indent=2))
        return 0 if res.is_valid else 1

    if args.policy_cmd == "inspect":
        info = inspect_effective_policy(policy)
        print(json.dumps(info, indent=2))
        return 0

    if args.policy_cmd == "simulate":
        query = PacketQuery(
            direction=Direction(args.direction),
            source_ip=args.src_ip,
            dest_ip=args.dst_ip,
            protocol=Protocol(args.protocol),
            source_port=args.src_port,
            dest_port=args.dst_port,
            interface=args.interface,
            application=args.application,
            established=args.established,
        )
        res = evaluate_packet(policy, query)
        print(json.dumps(res.to_dict(), indent=2))
        return 0

    if args.policy_cmd == "export":
        out = store.export_json(policy)
        if args.output:
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"Exported policy to {args.output}")
        else:
            print(out)
        audit.log("policy.export", details={"output": args.output or "stdout"})
        return 0

    if args.policy_cmd == "import":
        raw = Path(args.file).read_text(encoding="utf-8")
        try:
            imported, validation = parse_and_validate_import(raw)
        except PolicyImportError as exc:
            print(f"Import rejected: {exc}", file=sys.stderr)
            for detail in exc.details:
                print(f"  - {detail}", file=sys.stderr)
            audit.log("policy.import", outcome="rejected", details={"error": str(exc)})
            return 1
        store.save(imported)
        audit.log("policy.import", details={"rules": len(imported.rules)})
        print(f"Imported policy '{imported.name}' ({len(imported.rules)} rules).")
        for w in validation.warnings:
            print(f"WARNING: {w.message}")
        return 0

    return 1


def _cmd_rule(args: argparse.Namespace, store: PolicyStore, audit: AuditLogger) -> int:
    policy = store.load()

    if args.rule_cmd == "list":
        if not policy.rules:
            print("No rules configured.")
            return 0
        for idx, r in enumerate(policy.rules, start=1):
            print(f"{idx}. [{r.id}] {r.name} -> {explain_rule(r)}")
        return 0

    if args.rule_cmd == "add":
        schedule = (
            Schedule(expires_at=args.expires_at) if args.expires_at else None
        )
        rule = Rule(
            name=args.name,
            description=args.description or "",
            enabled=not args.disabled,
            direction=Direction(args.direction),
            action=Action(args.action),
            ip_version=IPVersion(args.ip_version),
            source_ips=args.src_ip or [],
            dest_ips=args.dst_ip or [],
            protocol=Protocol(args.protocol),
            source_ports=[PortRange.parse(p) for p in (args.src_port or [])],
            dest_ports=[PortRange.parse(p) for p in (args.dst_port or [])],
            interface=args.interface,
            application=args.application,
            schedule=schedule,
        )
        policy.rules.append(rule)
        val = validate_policy(policy)
        if not val.is_valid:
            for err in val.errors:
                print(f"ERROR [{err.code}]: {err.message}", file=sys.stderr)
            return 1
        store.save(policy)
        audit.log("rule.add", details={"rule_id": rule.id, "name": rule.name})
        print(f"Added rule '{rule.name}' ({rule.id}).")
        print(f"Explanation: {explain_rule(rule)}")
        for w in val.warnings:
            print(f"WARNING: {w.message}")
        return 0

    if args.rule_cmd == "remove":
        before = len(policy.rules)
        policy.rules = [r for r in policy.rules if r.id != args.id]
        if len(policy.rules) == before:
            print(f"Rule '{args.id}' not found.")
            return 1
        store.save(policy)
        audit.log("rule.remove", details={"rule_id": args.id})
        print(f"Removed rule '{args.id}'.")
        return 0

    if args.rule_cmd in ("enable", "disable"):
        target = next((r for r in policy.rules if r.id == args.id), None)
        if not target:
            print(f"Rule '{args.id}' not found.")
            return 1
        target.enabled = args.rule_cmd == "enable"
        store.save(policy)
        audit.log(f"rule.{args.rule_cmd}", details={"rule_id": args.id})
        print(f"Rule '{args.id}' {'enabled' if target.enabled else 'disabled'}.")
        return 0

    if args.rule_cmd == "move":
        idx = next((i for i, r in enumerate(policy.rules) if r.id == args.id), None)
        if idx is None:
            print(f"Rule '{args.id}' not found.")
            return 1
        new_idx = max(0, min(len(policy.rules) - 1, args.position - 1))
        rule = policy.rules.pop(idx)
        policy.rules.insert(new_idx, rule)
        store.save(policy)
        audit.log("rule.move", details={"rule_id": args.id, "position": new_idx + 1})
        print(f"Moved rule '{args.id}' to position {new_idx + 1}.")
        return 0

    if args.rule_cmd == "explain":
        target = next((r for r in policy.rules if r.id == args.id), None)
        if not target:
            print(f"Rule '{args.id}' not found.")
            return 1
        print(explain_rule(target))
        return 0

    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fireguard",
        description="Configurable, safety-first firewall policy manager (dry-run by default).",
    )
    parser.add_argument("--data-dir", help="Override FireGuard data directory.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # policy
    p_pol = sub.add_parser("policy", help="Manage firewall policy")
    pol_sub = p_pol.add_subparsers(dest="policy_cmd", required=True)
    p_init = pol_sub.add_parser("init", help="Initialize a new policy file")
    p_init.add_argument("--force", action="store_true")
    pol_sub.add_parser("show", help="Print current policy JSON")
    pol_sub.add_parser("validate", help="Validate current policy")
    pol_sub.add_parser("inspect", help="Inspect effective evaluation order")
    pol_sub.add_parser("starters", help="List available starter policies")
    p_ls = pol_sub.add_parser("load-starter", help="Load a starter policy (does not apply)")
    p_ls.add_argument("name")
    p_exp = pol_sub.add_parser("export", help="Export policy JSON")
    p_exp.add_argument("-o", "--output")
    p_imp = pol_sub.add_parser("import", help="Validate and import policy JSON")
    p_imp.add_argument("file")

    p_sim = pol_sub.add_parser("simulate", help="Simulate a packet against current policy")
    p_sim.add_argument("--direction", choices=["inbound", "outbound"], required=True)
    p_sim.add_argument("--src-ip", required=True)
    p_sim.add_argument("--dst-ip", required=True)
    p_sim.add_argument("--protocol", default="tcp")
    p_sim.add_argument("--src-port", type=int)
    p_sim.add_argument("--dst-port", type=int)
    p_sim.add_argument("--interface")
    p_sim.add_argument("--application")
    p_sim.add_argument("--established", action="store_true")

    # rule
    p_rule = sub.add_parser("rule", help="Manage individual rules")
    rule_sub = p_rule.add_subparsers(dest="rule_cmd", required=True)
    rule_sub.add_parser("list", help="List rules in precedence order")

    p_add = rule_sub.add_parser("add", help="Add a rule")
    p_add.add_argument("--name", required=True)
    p_add.add_argument("--description", default="")
    p_add.add_argument("--direction", choices=["inbound", "outbound"], required=True)
    p_add.add_argument("--action", choices=["allow", "block", "log"], required=True)
    p_add.add_argument("--ip-version", choices=["any", "ipv4", "ipv6"], default="any")
    p_add.add_argument("--protocol", default="any")
    p_add.add_argument("--src-ip", action="append")
    p_add.add_argument("--dst-ip", action="append")
    p_add.add_argument("--src-port", action="append")
    p_add.add_argument("--dst-port", action="append")
    p_add.add_argument("--interface")
    p_add.add_argument("--application")
    p_add.add_argument("--expires-at")
    p_add.add_argument("--disabled", action="store_true")

    for cmd_name in ("remove", "enable", "disable", "explain"):
        p_id = rule_sub.add_parser(cmd_name)
        p_id.add_argument("id")

    p_move = rule_sub.add_parser("move", help="Move rule to 1-based position")
    p_move.add_argument("id")
    p_move.add_argument("position", type=int)

    # preview
    p_prev = sub.add_parser("preview", help="Dry-run preview of rendered OS rules")
    p_prev.add_argument("--backend", default="auto")

    # apply
    p_app = sub.add_parser("apply", help="Apply policy to live OS firewall (requires confirmation)")
    p_app.add_argument("--backend", default="auto")
    p_app.add_argument("--yes", action="store_true", help="Skip initial APPLY prompt (still runs rollback guard)")

    # rollback
    p_rb = sub.add_parser("rollback", help="Restore firewall state from latest or specified snapshot")
    p_rb.add_argument("--backend", default="auto")
    p_rb.add_argument("--snapshot")

    # audit
    p_aud = sub.add_parser("audit", help="View recent audit log entries")
    p_aud.add_argument("--limit", type=int, default=25)

    # web
    p_web = sub.add_parser("web", help="Start local Web UI")
    p_web.add_argument("--host", default="127.0.0.1")
    p_web.add_argument("--port", type=int, default=8420)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    data_dir = Path(args.data_dir) if args.data_dir else None
    store = PolicyStore(data_dir)
    audit = AuditLogger(data_dir)

    if args.cmd == "policy":
        return _cmd_policy(args, store, audit)

    if args.cmd == "rule":
        return _cmd_rule(args, store, audit)

    if args.cmd == "preview":
        policy = store.load()
        backend = get_backend(args.backend)
        prev = backend.render_preview(policy)
        audit.log("policy.preview", details={"backend": backend.name})
        print(f"=== Dry-Run Preview ({prev.platform_name}) ===")
        for line in prev.summary:
            print(f"  * {line}")
        for w in prev.warnings:
            print(f"  ! WARNING: {w}")
        if prev.syntax_checked:
            print(f"  Syntax check: {'PASS' if prev.syntax_valid else 'FAIL'} ({prev.syntax_message})")
        print("\n--- Rendered Native Commands ---")
        print(prev.rendered_script)
        return 0

    if args.cmd == "apply":
        policy = store.load()
        backend = get_backend(args.backend)
        prev = backend.render_preview(policy)
        print(f"=== Apply Preview ({prev.platform_name}) ===")
        for line in prev.summary:
            print(f"  * {line}")
        for w in prev.warnings:
            print(f"  ! WARNING: {w}")
        if not args.yes:
            confirm = input("\nType 'APPLY' to modify live system firewall rules: ").strip()
            if confirm != "APPLY":
                print("Cancelled. No live changes made.")
                audit.log("policy.apply", outcome="cancelled", details={"backend": backend.name})
                return 1
        res = backend.apply_live(
            policy,
            store,
            confirm_callback=_interactive_connectivity_confirm,
            previous_policy=policy,
        )
        audit.log(
            "policy.apply",
            outcome="success" if res.success else "failed",
            details={"backend": backend.name, "rolled_back": res.rolled_back},
        )
        print(res.message)
        return 0 if res.success else 1

    if args.cmd == "rollback":
        backend = get_backend(args.backend)
        snap = store.load_snapshot(Path(args.snapshot) if args.snapshot else None)
        ok, msg = backend.rollback(snap)
        audit.log("policy.rollback", outcome="success" if ok else "failed", details={"backend": backend.name})
        print(msg)
        return 0 if ok else 1

    if args.cmd == "audit":
        for rec in audit.read_recent(args.limit):
            print(json.dumps(rec))
        return 0

    if args.cmd == "web":
        from fireguard.web.server import run_server

        run_server(host=args.host, port=args.port, data_dir=data_dir)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
