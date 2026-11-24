"""Tests for Linux nftables & Windows Defender backends (mocked) and CLI."""

from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fireguard.backends.linux_nft import LinuxNftablesBackend
from fireguard.backends.windows_fw import WindowsDefenderBackend
from fireguard.cli import main as cli_main
from fireguard.models import Action, Direction, IPVersion, Policy, PortRange, Protocol, Rule
from fireguard.storage import PolicyStore


def _sample_policy() -> Policy:
    return Policy(
        name="test-policy",
        rules=[
            Rule(
                id="allow-ssh",
                name="Allow SSH",
                direction=Direction.INBOUND,
                action=Action.ALLOW,
                ip_version=IPVersion.ANY,
                protocol=Protocol.TCP,
                dest_ports=[PortRange(22, 22)],
                source_ips=["192.168.1.0/24", "fd00::/64"],
            ),
            Rule(
                id="block-app",
                name="Block Tool",
                direction=Direction.OUTBOUND,
                action=Action.BLOCK,
                application="C:\\Tools\\bad.exe",
            ),
        ],
    )


class BackendsAndCliTests(unittest.TestCase):
    def test_linux_nft_preview_handles_dual_stack_and_flags_app_rule(self):
        backend = LinuxNftablesBackend()
        pol = _sample_policy()
        with patch("fireguard.backends.linux_nft.subprocess.run") as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
            preview = backend.render_preview(pol)

        self.assertIn("table inet fireguard", preview.rendered_script)
        self.assertIn("ip saddr 192.168.1.0/24 tcp dport 22 accept", preview.rendered_script)
        self.assertIn("ip6 saddr fd00::/64 tcp dport 22 accept", preview.rendered_script)
        self.assertEqual(len(preview.unsupported_rules), 1)
        self.assertEqual(preview.unsupported_rules[0]["rule_id"], "block-app")

    def test_linux_nft_apply_and_rollback_when_confirmation_fails(self):
        backend = LinuxNftablesBackend()
        pol = Policy(
            rules=[
                Rule(
                    id="allow-https",
                    name="Allow HTTPS",
                    direction=Direction.INBOUND,
                    action=Action.ALLOW,
                    protocol=Protocol.TCP,
                    dest_ports=[PortRange(443, 443)],
                )
            ]
        )

        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(Path(tmp))
            with (
                patch.object(backend, "check_availability", return_value=(True, "ok")),
                patch.object(backend, "is_elevated", return_value=True),
                patch("fireguard.backends.linux_nft.subprocess.run") as mock_run,
            ):
                mock_run.side_effect = [
                    SimpleNamespace(returncode=0, stdout="", stderr=""),
                    SimpleNamespace(returncode=1, stdout="", stderr="No such file"),
                    SimpleNamespace(returncode=0, stdout="", stderr=""),
                    SimpleNamespace(returncode=0, stdout="", stderr=""),
                ]
                res = backend.apply_live(
                    pol, store, confirm_callback=lambda _t: False, previous_policy=pol
                )

            self.assertFalse(res.success)
            self.assertTrue(res.rolled_back)
            self.assertIsNotNone(res.snapshot_path)
            self.assertEqual(len(store.list_snapshots()), 1)

    def test_windows_defender_preview_supports_application_and_escapes_quotes(self):
        backend = WindowsDefenderBackend()
        pol = _sample_policy()
        preview = backend.render_preview(pol)

        self.assertIn("Remove-NetFirewallRule -Group 'FireGuard'", preview.rendered_script)
        self.assertIn("New-NetFirewallRule", preview.rendered_script)
        self.assertIn("-Program 'C:\\Tools\\bad.exe'", preview.rendered_script)

    def test_cli_dry_run_workflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(cli_main(["--data-dir", tmp, "policy", "init"]), 0)
            self.assertEqual(
                cli_main(
                    [
                        "--data-dir",
                        tmp,
                        "rule",
                        "add",
                        "--name",
                        "Allow HTTPS",
                        "--direction",
                        "inbound",
                        "--action",
                        "allow",
                        "--protocol",
                        "tcp",
                        "--dst-port",
                        "443",
                    ]
                ),
                0,
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["--data-dir", tmp, "preview", "--backend", "linux-nftables"])
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("Dry-Run Preview", out)
            self.assertIn("tcp dport 443 accept", out)

            sim_buf = io.StringIO()
            with redirect_stdout(sim_buf):
                rc2 = cli_main(
                    [
                        "--data-dir",
                        tmp,
                        "policy",
                        "simulate",
                        "--direction",
                        "inbound",
                        "--src-ip",
                        "198.51.100.1",
                        "--dst-ip",
                        "10.0.0.1",
                        "--protocol",
                        "tcp",
                        "--dst-port",
                        "443",
                    ]
                )
            self.assertEqual(rc2, 0)
            self.assertIn('"verdict": "allow"', sim_buf.getvalue())
