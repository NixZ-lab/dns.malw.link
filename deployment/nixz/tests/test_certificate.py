from pathlib import Path
import subprocess
import sys
import unittest


class CertificateEmailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (Path(__file__).resolve().parents[1] / 'certificate.sh').read_text()
        cls.validator = source.split('python3 - "$email" <<\'PY\'\n', 1)[1].split('\nPY', 1)[0]

    def validate(self, address):
        return subprocess.run([sys.executable, '-c', self.validator, address], capture_output=True)

    def test_ascii_email_accepted(self):
        for address in ['user@example.net', 'user.name+acme@example.net']:
            with self.subTest(address=address):
                self.assertEqual(self.validate(address).returncode, 0)

    def test_corrupt_and_non_ascii_input_rejected_cleanly(self):
        for address in [b'\xd1user@example.net', '\u044fu@example.net', '\u200buser@example.net',
                        'user@example.net\r', 'user @example.net', '', 'user@@example.net']:
            with self.subTest(address=repr(address)):
                result = self.validate(address)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'Invalid ACME email', result.stderr)
                self.assertNotIn(b'Traceback', result.stderr)
                self.assertNotIn(b'user@example.net', result.stderr)


if __name__ == '__main__':
    unittest.main()
