import json
import unittest

from sanctum.redaction import Policy, Redactor, RedactionError, restore_with_mapping
from sanctum.protocol import Session, dumps


class RedactionTests(unittest.TestCase):
    def test_roundtrip_and_stability(self):
        r = Redactor()
        original = '11.111.111.11 demo@example.com password="a complicated value" 11.111.111.11'
        safe = r.text(original)
        self.assertEqual(safe.count("[IP-1]"), 2)
        self.assertIn("[EMAIL-1]", safe)
        self.assertNotIn("complicated", safe)
        self.assertEqual(r.restore(safe), original)
        self.assertEqual(r.text("11.111.111.11"), "[IP-1]")

    def test_ipv6_and_invalid_addresses(self):
        r = Redactor()
        safe = r.text("::1 2001:db8::1 [fe80::1%eth0]:443 999.1.1.1 v1.2.3")
        self.assertIn("[IP-1]", safe)
        self.assertIn("[IP-2]", safe)
        self.assertIn("[[IP-3]]:443", safe)
        self.assertIn("999.1.1.1", safe)
        self.assertIn("v1.2.3", safe)

    def test_password_assignments(self):
        for text, secret in [('password=abc123', 'abc123'), ('"password": "abc 123"', 'abc 123'), ("токен='value123'", 'value123'), ('API_KEY=key123456', 'key123456'), ('token=abcdef', 'abcdef'), ('AWS_SECRET_ACCESS_KEY=aws-secret', 'aws-secret')]:
            with self.subTest(text=text):
                r = Redactor()
                self.assertNotIn(secret, r.text(text))

    def test_known_signatures(self):
        for value in ('sk-proj-' + 'a' * 30, 'ghp_' + 'a' * 30, 'AKIA' + 'A' * 16, 'xoxb-' + 'a' * 30, 'eyJabc.eyJdef.signature'):
            with self.subTest(value=value):
                self.assertNotIn(value, Redactor().text(value))

    def test_pem_is_one_secret(self):
        original = '-----BEGIN RSA PRIVATE KEY-----\nDATA\n-----END RSA PRIVATE KEY-----'
        r = Redactor()
        self.assertEqual(r.text(original), '[PRIVATE_KEY-1]')
        self.assertEqual(r.restore('[PRIVATE_KEY-1]'), original)

    def test_bearer_and_url_auth(self):
        r = Redactor()
        safe = r.text('Authorization: Bearer abc.def.ghi https://user:pass@example.org/path')
        self.assertNotIn('abc.def.ghi', safe)
        self.assertNotIn('user:pass', safe)

    def test_structured_and_serialized_json(self):
        r = Redactor()
        value = {'outer': [{'password': 'has spaces', 'output': '{"token":"hidden-value"}', 'email': 'demo@example.com'}]}
        safe = r.value(value)
        wire = dumps(safe)
        self.assertNotIn('has spaces', wire)
        self.assertNotIn('hidden-value', wire)
        self.assertNotIn('demo@example.com', wire)
        self.assertEqual(json.loads(safe['outer'][0]['output'])['token'], '[SECRET-2]')

    def test_learned_secret_without_label(self):
        r = Redactor()
        r.text('password=sensitive-alone')
        self.assertEqual(r.text('sensitive-alone'), '[SECRET-1]')

    def test_discover_secret_later_in_same_payload(self):
        s = Session(Redactor())
        safe = s.request({'input': ['secret-standalone', {'password': 'secret-standalone'}]})
        self.assertNotIn('secret-standalone', dumps(safe))

    def test_custom_secrets(self):
        r = Redactor(Policy(('ACME-INTERNAL',)))
        self.assertEqual(r.text('ACME-INTERNAL ACME-INTERNAL'), '[CUSTOM-1] [CUSTOM-1]')

    def test_literal_placeholder_does_not_collide(self):
        r = Redactor()
        self.assertEqual(r.text('[IP-1] 1.2.3.4'), '[IP-1] [IP-2]')
        self.assertEqual(r.restore('[IP-1] [IP-2]'), '[IP-1] 1.2.3.4')

    def test_literal_placeholder_reserved_across_whole_request(self):
        s = Session(Redactor())
        safe = s.request({'input': ['1.2.3.4', 'Example: [IP-1]']})
        self.assertEqual(safe['input'], ['[IP-2]', 'Example: [IP-1]'])

    def test_literal_token_inside_a_password_does_not_prevent_redaction(self):
        r = Redactor()
        original = 'password="before [IP-1] after"'
        safe = r.text(original)
        self.assertNotIn('before', safe)
        self.assertEqual(r.restore(safe), original)

    def test_existing_tokens_are_idempotent(self):
        r = Redactor()
        safe = r.text('password=abcdef')
        self.assertEqual(r.text(safe), safe)

    def test_capacity_fails_closed(self):
        r = Redactor(Policy(max_entries=1))
        with self.assertRaises(RedactionError):
            r.text('1.1.1.1 2.2.2.2')

    def test_invalid_policy_does_not_echo(self):
        for data in ({'literals': ['']}, {'max_entries': True}, {'max_entries': 0}):
            with self.assertRaises(RedactionError):
                Policy(**data)

    def test_mapping_validation(self):
        with self.assertRaises(RedactionError):
            restore_with_mapping('[IP-1]', {'other': 'secret'})
        self.assertEqual(restore_with_mapping('[IP-1]', {'[IP-1]': '1.2.3.4'}), '1.2.3.4')

    def test_nested_numeric_password(self):
        self.assertEqual(Redactor().value({'password': 123456})['password'], '[SECRET-1]')

    def test_overlapping_secret_does_not_expose_suffix(self):
        r = Redactor(Policy(('abc', 'abcdef')))
        self.assertEqual(r.text('abcdef'), '[CUSTOM-1]')

    def test_known_ip_inside_new_password_does_not_expose_remainder(self):
        for password in ('1.2.3.4-sensitive-suffix', 'sensitive-prefix-1.2.3.4'):
            with self.subTest(password=password):
                r = Redactor()
                r.text('1.2.3.4')
                original = f'password="{password}"'
                masked = r.text(original)
                self.assertNotIn('sensitive', masked)
                self.assertEqual(r.restore(masked), original)

    def test_crossing_url_and_email_detections_hide_full_credential(self):
        r = Redactor()
        original = 'https://synthetic-user:synthetic-password@example.com/path'
        safe = r.text(original)
        self.assertNotIn('synthetic-user', safe)
        self.assertNotIn('synthetic-password', safe)
        self.assertEqual(r.restore(safe), original)

    def test_plain_unlabelled_password_is_not_claimed_detectable(self):
        self.assertEqual(Redactor().text('randomword123'), 'randomword123')


if __name__ == '__main__':
    unittest.main()
