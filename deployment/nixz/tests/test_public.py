import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_routes import RoutesTests

spec = importlib.util.spec_from_file_location('guard', Path(__file__).resolve().parents[1] / 'public-guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class PublicRoutesTests(RoutesTests):
    def public_node(self):
        self.node.update(tls=True, hostname='dns.test.invalid', access_mode='public', public_access_ack=True)

    def test_public_requires_ack_and_ipv4_tls(self):
        self.public_node()
        for key, value in [('public_access_ack', False), ('tls', False), ('ipv6_verified', True)]:
            old = self.node[key]
            self.node[key] = value
            with self.assertRaises(ValueError): self.parsed()
            self.node[key] = old

    def test_dns_identity_and_tls_passthrough_split(self):
        self.public_node()
        release = self.render()
        nginx = (release / 'nginx.conf').read_text()
        dns = (release / 'dnsdist.conf').read_text()
        self.assertIn('proxy_protocol v2;', nginx)
        self.assertIn('listen 127.0.0.1:9446 proxy_protocol;', nginx)
        self.assertIn('proxy_protocol off;', nginx)
        self.assertIn('limit_conn global 64;', nginx)
        self.assertIn('MaxQPSIPRule(80, 32, 64, 120)', dns)
        self.assertIn('proxyProtocolOutsideTLS=true', dns)
        self.assertIn('setProxyProtocolACL({"127.0.0.1/32"})', dns)
        self.assertIn('setLocal("127.0.0.1:5300", {enableProxyProtocol=false})', dns)
        self.assertNotIn('0.0.0.0:53', dns)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.state = dict(rx=100, tx=200, used=10, budget=1000, boot='boot1', day='2026-10-12', latched=False)

    def test_accounting_and_stop(self):
        state, why = guard.evaluate(self.state, 150, 250, 'boot1', '2026-10-12')
        self.assertEqual(state['used'], 110)
        self.assertIsNone(why)
        _, why = guard.evaluate(state, 1150, 250, 'boot1', '2026-10-12')
        self.assertIsNotNone(why)

    def test_reboot_counter_reset_and_latch_fail_closed(self):
        for rx, tx, boot in [(99, 200, 'boot1'), (100, 199, 'boot1'), (100, 200, 'boot2')]:
            self.assertIsNotNone(guard.evaluate(self.state, rx, tx, boot, '2026-10-12')[1])
        self.state['latched'] = True
        self.assertIsNotNone(guard.evaluate(self.state, 100, 200, 'boot1', '2026-10-13')[1])

    def test_day_rollover_does_not_hide_overrun(self):
        _, why = guard.evaluate(self.state, 1100, 200, 'boot1', '2026-10-13')
        self.assertIsNotNone(why)

    def test_ufw_add_delete_and_preflight_are_valid_commands(self):
        with patch.object(guard.subprocess, 'run') as run:
            guard.rule('allow', 443)
            self.assertEqual(run.call_args.args[0], ['ufw', 'allow', 'from', '0.0.0.0/0', 'to', 'any', 'port', '443', 'proto', 'tcp'])
            guard.rule('delete', 853)
            self.assertEqual(run.call_args.args[0], ['ufw', '--force', 'delete', 'allow', 'from', '0.0.0.0/0', 'to', 'any', 'port', '853', 'proto', 'tcp'])
            guard.rule('allow', 853, dry_run=True)
            self.assertEqual(run.call_args.args[0], ['ufw', '--dry-run', 'allow', 'from', '0.0.0.0/0', 'to', 'any', 'port', '853', 'proto', 'tcp'])
            for action, port in [('allow', 22), ('allow', 53), ('reset', 443)]:
                with self.assertRaises(ValueError): guard.rule(action, port)
