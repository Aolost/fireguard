"""Tests for policy models, validation, conflict detection, and precedence engine."""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from fireguard.audit import AuditLogger
from fireguard.engine import PacketQuery, evaluate_packet, inspect_effective_policy, starter_policies
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
from fireguard.storage import PolicyImportError, parse_and_validate_import
from fireguard.validation import validate_policy, validate_rule


class ValidationAndEngineTests(unittest.TestCase):
    def test_rule_validation_rejects_ip_version_mismatch_and_invalid_ports(self):
        bad_ip = Rule(
            id="r1",
            name="Mismatch",
            ip_version=IPVersion.IPV4,
            source_ips=["2001:db8::/32"],
        )
        res = validate_rule(bad_ip)
        self.assertFalse(res.is_valid)
        self.assertTrue(any(e.code == "ip_version_mismatch" for e in res.errors))

        bad_port = Rule(
            id="r2",
            name="Bad Port",
            protocol=Protocol.ICMP,
            dest_ports=[PortRange(80, 80)],
        )
        res2 = validate_rule(bad_port)
        self.assertFalse(res2.is_valid)
        self.assertTrue(any(e.code == "ports_require_transport_protocol" for e in res2.errors))

    def test_safety_warnings_for_critical_services_and_block_all(self):
        rule = Rule(
            id="block-ssh",
            name="Block SSH",
            direction=Direction.INBOUND,
            action=Action.BLOCK,
            protocol=Protocol.TCP,
            dest_ports=[PortRange(22, 22)],
        )
        res = validate_rule(rule)
        self.assertTrue(res.is_valid)
        self.assertTrue(any(w.code == "blocks_critical_service" for w in res.warnings))

        block_all = Rule(
            id="block-all-in",
            name="Block All Inbound",
            direction=Direction.INBOUND,
            action=Action.BLOCK,
        )
        res_all = validate_rule(block_all)
        self.assertTrue(any(w.code == "block_all_traffic" for w in res_all.warnings))
        self.assertIn("WARNING:", explain_rule(block_all))

    def test_conflict_and_shadowing_detection(self):
        r1 = Rule(
            id="broad-allow",
            name="Allow All TCP",
            direction=Direction.INBOUND,
            action=Action.ALLOW,
            protocol=Protocol.TCP,
        )
        r2 = Rule(
            id="narrow-block",
            name="Block TCP 22",
            direction=Direction.INBOUND,
            action=Action.BLOCK,
            protocol=Protocol.TCP,
            dest_ports=[PortRange(22, 22)],
        )
        policy = Policy(rules=[r1, r2])
        res = validate_policy(policy)
        self.assertTrue(
            any(w.code == "rule_shadowed" and w.rule_id == "narrow-block" for w in res.warnings)
        )

    def test_precedence_loopback_established_log_and_ipv6(self):
        log_rule = Rule(
            id="log-ssh",
            name="Log SSH",
            direction=Direction.INBOUND,
            action=Action.LOG,
            protocol=Protocol.TCP,
            dest_ports=[PortRange(22, 22)],
        )
        allow_ssh = Rule(
            id="allow-ssh",
            name="Allow SSH",
            direction=Direction.INBOUND,
            action=Action.ALLOW,
            ip_version=IPVersion.ANY,
            protocol=Protocol.TCP,
            dest_ports=[PortRange(22, 22)],
        )
        policy = Policy(
            defaults=SystemDefaults(
                default_inbound=Action.BLOCK,
                default_outbound=Action.ALLOW,
                allow_loopback=True,
                allow_established=True,
            ),
            rules=[log_rule, allow_ssh],
        )

        res_lo = evaluate_packet(
            policy,
            PacketQuery(Direction.INBOUND, "127.0.0.1", "127.0.0.1", Protocol.TCP, dest_port=9999),
        )
        self.assertEqual(res_lo.verdict, Action.ALLOW)
        self.assertEqual(res_lo.matched_by, "system:loopback")

        res_est = evaluate_packet(
            policy,
            PacketQuery(
                Direction.INBOUND, "1.2.3.4", "10.0.0.5", Protocol.TCP, dest_port=443, established=True
            ),
        )
        self.assertEqual(res_est.verdict, Action.ALLOW)
        self.assertEqual(res_est.matched_by, "system:established")

        res_v6 = evaluate_packet(
            policy,
            PacketQuery(Direction.INBOUND, "2001:db8::1", "2001:db8::2", Protocol.TCP, dest_port=22),
        )
        self.assertEqual(res_v6.verdict, Action.ALLOW)
        self.assertEqual(res_v6.matched_by, "rule:allow-ssh")
        self.assertEqual(res_v6.logged_by, ["log-ssh"])

        res_v6_drop = evaluate_packet(
            policy,
            PacketQuery(Direction.INBOUND, "2001:db8::1", "2001:db8::2", Protocol.TCP, dest_port=8080),
        )
        self.assertEqual(res_v6_drop.verdict, Action.BLOCK)
        self.assertEqual(res_v6_drop.matched_by, "default:inbound")

    def test_expired_schedule_is_skipped(self):
        expired = Rule(
            id="temp-allow",
            name="Temp Allow",
            direction=Direction.INBOUND,
            action=Action.ALLOW,
            protocol=Protocol.TCP,
            dest_ports=[PortRange(8080, 8080)],
            schedule=Schedule(expires_at="2020-01-01T00:00:00Z"),
        )
        policy = Policy(rules=[expired])
        res = evaluate_packet(
            policy,
            PacketQuery(Direction.INBOUND, "1.2.3.4", "10.0.0.2", Protocol.TCP, dest_port=8080),
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(res.verdict, Action.BLOCK)
        self.assertEqual(res.matched_by, "default:inbound")

    def test_import_rejects_malformed_and_unknown_fields(self):
        with self.assertRaises(PolicyImportError):
            parse_and_validate_import("{bad json")

        with self.assertRaises(PolicyImportError):
            parse_and_validate_import(json.dumps({"version": 1, "unknown_key": 123}))

        with self.assertRaises(PolicyImportError):
            parse_and_validate_import(
                json.dumps({"version": 1, "rules": [{"name": "x", "evil": True}]})
            )

    def test_starter_policies_and_audit_redaction(self):
        starters = starter_policies()
        self.assertIn("workstation-strict", starters)
        for pol in starters.values():
            self.assertTrue(validate_policy(pol).is_valid)
            insp = inspect_effective_policy(pol)
            self.assertTrue(insp["ipv6_consistent"])

        with tempfile.TemporaryDirectory() as tmp:
            audit = AuditLogger(Path(tmp))
            audit.log("test.event", details={"api_key": "super-secret", "rule_id": "r1"})
            entries = audit.read_recent(10)
            self.assertEqual(entries[0]["details"]["api_key"], "[REDACTED]")
            self.assertEqual(entries[0]["details"]["rule_id"], "r1")
