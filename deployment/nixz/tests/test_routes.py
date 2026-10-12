import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nixz import ROOT, compile_release, load, public_ip


class RoutesTests(unittest.TestCase):
    def setUp(self):
        self.routes = json.loads((ROOT / 'routes.json').read_text())
        self.node = json.loads((ROOT / 'node.json.example').read_text())
        self.node['client_cidrs'] = ['8.8.8.8/32']
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def parsed(self):
        (self.path / 'r.json').write_text(json.dumps(self.routes))
        (self.path / 'n.json').write_text(json.dumps(self.node))
        return load(self.path / 'r.json', self.path / 'n.json')

    def render(self, pins=None):
        r, n, p, rec = self.parsed()
        pins = pins or {d: ['104.18.32.7'] for d in p}
        compile_release(r, n, p, rec, pins, self.path / 'release')
        return self.path / 'release'

    def test_no_open_acl(self):
        self.node['client_cidrs'] = []
        with self.assertRaises(ValueError): self.parsed()
        self.node['client_cidrs'] = ['0.0.0.0/0']
        with self.assertRaises(ValueError): self.parsed()
        self.node['client_cidrs'] = ['8.0.0.0/8']
        with self.assertRaises(ValueError): self.parsed()

    def test_private_reserved_and_self_pins_rejected(self):
        for ip in ['127.0.0.1', '10.0.0.1', '169.254.169.254', '100.64.0.1',
                   '192.0.2.1', '224.0.0.1', '::1', 'fc00::1', 'fe80::1']:
            with self.subTest(ip=ip), self.assertRaises(ValueError): public_ip(ip)
        _, _, proxy, _ = self.parsed()
        with self.assertRaises(ValueError):
            self.render({d: ['2.27.16.203'] for d in proxy})

    def test_exact_domain_validation_and_conflicts(self):
        original = copy.deepcopy(self.routes)
        for value in ['*.openai.com', '.openai.com', 'OPENAI.com', 'x;return.com', 'openai.com.', 'openai..com']:
            self.routes = copy.deepcopy(original)
            self.routes['groups']['openai-test'] = [value]
            with self.assertRaises(ValueError): self.parsed()
        self.routes = original
        self.routes['blocked'] = ['chatgpt.com']
        with self.assertRaises(ValueError): self.parsed()

    def test_exclusion_removes_all_exports(self):
        self.routes['exclude'] = ['auth.openai.com']
        release = self.render()
        for file in ['nginx.conf', 'dnsdist.conf', 'hosts', 'adguard.txt']:
            self.assertNotIn('auth.openai.com', (release / file).read_text())

    def test_ipv4_only_no_ech_no_loop(self):
        release = self.render()
        conf = (release / 'dnsdist.conf').read_text()
        self.assertIn('QTypeRule(65)', conf)
        self.assertIn('QTypeRule(64)', conf)
        self.assertIn('DNSQType.AAAA', conf)
        self.assertNotIn('setACL({"0.0.0.0/0"', conf)
        self.assertNotIn('0.0.0.0:53', conf)
        nginx = (release / 'nginx.conf').read_text()
        self.assertNotIn('proxy_pass $ssl_preread_server_name', nginx)
        self.assertNotIn('resolver ', nginx)
        self.assertNotIn('listen [::]', nginx)
        self.assertIn('default 127.0.0.1:9444;', nginx)

    def test_tls_requires_real_hostname(self):
        self.node['tls'] = True
        with self.assertRaises(ValueError): self.parsed()
        self.node['hostname'] = 'dns.test.invalid'
        release = self.render()
        self.assertIn('127.0.0.1:8443', (release / 'nginx.conf').read_text())
        self.assertIn('127.0.0.1:8853', (release / 'dnsdist.conf').read_text())

    def test_ipv6_only_after_verification(self):
        self.node['ipv6_verified'] = True
        release = self.render()
        self.assertIn('2a0d:d940:1a:960::2', (release / 'hosts').read_text())
        self.assertIn('listen [::]:443', (release / 'nginx.conf').read_text())


if __name__ == '__main__':
    unittest.main()
