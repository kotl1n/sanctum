from contextlib import redirect_stdout
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

from sanctum.cli import prepare
from sanctum.demo import run, running
from sanctum.gateway import Gateway, Settings, MAX_BODY
from sanctum.protocol import dumps


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.received = []
        self.upstream_status = 200
        self.upstream_redirect = None
        self.reply = {'id': 'resp_1', 'output': []}
        outer = self
        class Provider(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                raw = self.rfile.read(int(self.headers['Content-Length']))
                outer.received.append((raw, dict(self.headers), self.path))
                self.send_response(outer.upstream_status)
                self.send_header('Content-Type', 'application/json')
                if outer.upstream_redirect:
                    self.send_header('Location', outer.upstream_redirect)
                self.end_headers()
                self.wfile.write(dumps(outer.reply).encode())
        self.upstream = self.enterContext(running(ThreadingHTTPServer(('127.0.0.1', 0), Provider)))
        self.key = secrets.token_urlsafe(32)
        self.settings = Settings(local_key=self.key, test_upstream=f'http://127.0.0.1:{self.upstream.server_port}/backend-api/codex')
        self.gateway = self.enterContext(running(Gateway(('127.0.0.1', 0), self.settings)))
        self.base = f'http://127.0.0.1:{self.gateway.server_port}'

    def send(self, payload, *, headers=None, path='/backend-api/codex/responses', raw=None):
        combined = {'Content-Type': 'application/json', 'Authorization': 'Bearer synthetic-upstream-credential', 'X-Sanctum-Key': self.key, 'session_id': 'synthetic-session-1'}
        combined.update(headers or {})
        req = urllib.request.Request(self.base + path, data=raw if raw is not None else dumps(payload).encode(), headers=combined)
        try:
            response = urllib.request.urlopen(req, timeout=3)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read())

    def test_on_wire_body_and_header_boundary(self):
        payload = {'input': [{'role': 'user', 'content': '11.111.111.11 demo@example.com password=hidden-value'}, {'type': 'function_call_output', 'output': 'hidden-value'}]}
        status, _ = self.send(payload, headers={'Cookie': 'secret-cookie', 'X-Extra': 'secret-extra', 'ChatGPT-Account-ID': 'synthetic-account'})
        self.assertEqual(status, 200)
        raw, headers, path = self.received[0]
        self.assertEqual(path, '/backend-api/codex/responses')
        for value in (b'11.111.111.11', b'demo@example.com', b'hidden-value'):
            self.assertNotIn(value, raw)
        lowered = {k.lower(): v for k, v in headers.items()}
        self.assertEqual(lowered['authorization'], 'Bearer synthetic-upstream-credential')
        self.assertEqual(lowered['chatgpt-account-id'], 'synthetic-account')
        self.assertNotIn('x-sanctum-key', lowered)
        self.assertNotIn('cookie', lowered)
        self.assertNotIn('x-extra', lowered)
        self.assertFalse(json.loads(raw)['store'])

    def test_local_auth_and_browser_rejection(self):
        for headers, status in (({'X-Sanctum-Key': 'wrong'}, 401), ({'Origin': 'https://evil.example'}, 403)):
            self.assertEqual(self.send({'input': 'hello'}, headers=headers)[0], status)
        self.assertFalse(self.received)

    def test_gateway_and_provider_credentials_cannot_be_echoed_in_context(self):
        status, _ = self.send({'input': [self.key, 'synthetic-upstream-credential']})
        self.assertEqual(status, 200)
        raw, _, _ = self.received[0]
        self.assertNotIn(self.key.encode(), raw)
        self.assertNotIn(b'synthetic-upstream-credential', raw)

    def test_unknown_routes_and_queries_rejected(self):
        for path in ('/v1/files', '/backend-api/codex/responses?secret=value', '/backend-api/codex/../responses', '/responses'):
            with self.subTest(path=path):
                self.assertEqual(self.send({'input': 'hello'}, path=path)[0], 400)
        self.assertFalse(self.received)

    def test_malformed_duplicate_nonfinite_json_rejected(self):
        for raw in (b'{bad', b'{"input":"a","input":"b"}', b'{"input":NaN}', b'[]', b'\xff'):
            with self.subTest(raw=raw):
                self.assertEqual(self.send(None, raw=raw)[0], 400)
        self.assertFalse(self.received)

    def test_attachments_rejected_before_contact(self):
        status, _ = self.send({'input': [{'type': 'input_image', 'image_url': 'data:image/png;base64,secret'}]})
        self.assertEqual(status, 400)
        self.assertFalse(self.received)

    def test_error_body_never_echoes_raw_input(self):
        self.upstream_status = 429
        self.reply = {'error': 'synthetic-upstream-credential password=leaky'}
        status, body = self.send({'input': 'hello'})
        self.assertEqual(status, 429)
        self.assertNotIn('credential', dumps(body))
        self.assertNotIn('leaky', dumps(body))

    def test_redirect_not_followed(self):
        self.upstream_status = 307
        self.upstream_redirect = self.base + '/should-never-receive-auth'
        status, _ = self.send({'input': 'hello'})
        self.assertEqual(status, 502)
        self.assertEqual(len(self.received), 1)

    def test_tool_restoration_and_session_isolation(self):
        self.send({'input': '11.111.111.11'})
        self.send({'input': '22.222.222.22'}, headers={'session_id': 'synthetic-session-2'})
        self.reply = {'output': [{'type': 'function_call', 'name': 'connect', 'arguments': '{"host":"[IP-1]"}'}]}
        _, first = self.send({'input': 'hello'})
        _, second = self.send({'input': 'hello'}, headers={'session_id': 'synthetic-session-2'})
        self.assertEqual(json.loads(first['output'][0]['arguments'])['host'], '11.111.111.11')
        self.assertEqual(json.loads(second['output'][0]['arguments'])['host'], '22.222.222.22')

    def test_no_restore_option(self):
        self.settings.restore_tools = False
        self.reply = {'output': [{'type': 'function_call', 'name': 'connect', 'arguments': '{"host":"[IP-1]"}'}]}
        _, body = self.send({'input': '11.111.111.11'})
        self.assertIn('[IP-1]', body['output'][0]['arguments'])

    def test_invalid_session_rejected(self):
        status, _ = self.send({'input': 'hello'}, headers={'session_id': 'demo@example.com'})
        self.assertEqual(status, 400)
        self.assertFalse(self.received)

    def test_session_capacity_does_not_evict_live_vault(self):
        self.settings.max_sessions = 1
        self.assertEqual(self.send({'input': '11.111.111.11'})[0], 200)
        self.assertEqual(self.send({'input': '22.222.222.22'}, headers={'session_id': 'synthetic-session-2'})[0], 400)
        self.assertEqual(self.send({'input': '[IP-1]'})[0], 200)

    def test_chunked_and_oversized_bodies_rejected(self):
        for headers in ({'Transfer-Encoding': 'chunked', 'Content-Length': '1'}, {'Content-Length': str(MAX_BODY + 1)}):
            connection = http.client.HTTPConnection('127.0.0.1', self.gateway.server_port, timeout=3)
            connection.request('POST', '/backend-api/codex/responses', body=b'x', headers={'X-Sanctum-Key': self.key, **headers})
            response = connection.getresponse()
            self.assertIn(response.status, (400, 413))
            response.read()
            connection.close()
        self.assertFalse(self.received)

    def test_non_loopback_bind_and_weak_key_rejected(self):
        with self.assertRaises(ValueError):
            Gateway(('0.0.0.0', 0), self.settings)
        with self.assertRaises(ValueError):
            Settings(local_key='weak')


class CLITests(unittest.TestCase):
    def test_prepare_permissions_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            with redirect_stdout(io.StringIO()):
                prepare(Path(directory), 47631, 'chatgpt')
            for name in ('connection.json', 'codex.fragment.toml'):
                self.assertEqual((Path(directory) / name).stat().st_mode & 0o777, 0o600)
            config = (Path(directory) / 'codex.fragment.toml').read_text()
            import tomllib
            self.assertTrue(tomllib.loads(config)['model_providers']['sanctum']['requires_openai_auth'])
            with self.assertRaises(ValueError):
                prepare(Path(directory), 47631, 'chatgpt')

    def test_cli_redact_restore_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = str(Path(directory) / 'private.vault.json')
            original = '11.111.111.11 demo@example.com password=synthetic-password'
            masked = subprocess.run([sys.executable, '-m', 'sanctum', 'redact', '--vault', vault], input=original, capture_output=True, text=True, check=True)
            self.assertNotIn('11.111.111.11', masked.stdout)
            restored = subprocess.run([sys.executable, '-m', 'sanctum', 'restore', '--vault', vault], input=masked.stdout, capture_output=True, text=True, check=True)
            self.assertEqual(restored.stdout, original)

    def test_prompt_guard_blocks_without_echo(self):
        result = subprocess.run([sys.executable, 'scripts/prompt_guard.py'], input=dumps({'hook_event_name': 'UserPromptSubmit', 'prompt': 'password=synthetic-hidden-value'}), capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['decision'], 'block')
        self.assertNotIn('synthetic-hidden-value', result.stdout + result.stderr)

    def test_demo_entire_gateway_tool_loop(self):
        output = io.StringIO()
        with redirect_stdout(output):
            run()
        self.assertIn('PASS:', output.getvalue())


if __name__ == '__main__':
    unittest.main()
