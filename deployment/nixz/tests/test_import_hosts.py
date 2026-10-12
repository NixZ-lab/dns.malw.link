from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from import_hosts import catalogue


class ImportTests(unittest.TestCase):
    def test_ips_discarded_deduplicated_and_never_enabled(self):
        result = catalogue('# Example\n192.0.2.1 service.example\n198.51.100.1 service.example\n')
        self.assertEqual(result['groups'], {'Example': ['service.example']})
        self.assertEqual(result['enabled_groups'], [])
        self.assertNotIn('192.0.2.1', str(result))

    def test_legacy_endpoints_excluded(self):
        result = catalogue('# Работающие IP без прокси\n127.0.0.1 localhost\n192.0.2.1 dnstest.geohide.ru\n# Example\n192.0.2.2 service.example\n')
        self.assertNotIn('dnstest.geohide.ru', str(result['groups']))

    def test_invalid_or_wildcard_name_aborts(self):
        for name in ['*.example.com', 'x;bad.example', 'singlelabel']:
            with self.assertRaises(ValueError): catalogue('192.0.2.1 ' + name)
