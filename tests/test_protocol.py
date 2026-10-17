import io
import json
import unittest

from sanctum.protocol import Session, ResponseStream, dumps
from sanctum.redaction import Redactor, RedactionError


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.session = Session(Redactor())
        self.session.request({'input': '11.111.111.11 email demo@example.com password="quote\"$ danger"'})

    def test_tool_json_restores_escaping(self):
        s = Session(Redactor())
        s.request({'input': {'password': 'quote"back\\line\n'}})
        restored = s.arguments('{"password":"[SECRET-1]"}', 'database_connect')
        self.assertEqual(json.loads(restored)['password'], 'quote"back\\line\n')

    def test_shell_ip_restored(self):
        args = self.session.arguments('{"cmd":"ping [IP-1]"}', 'exec_command')
        self.assertEqual(json.loads(args)['cmd'], 'ping 11.111.111.11')

    def test_unsafe_shell_secret_blocked(self):
        s = Session(Redactor())
        s.request({'input': {'password': '$(touch /tmp/never)'}})
        for tool in ('exec_command', 'generic_tool'):
            with self.subTest(tool=tool), self.assertRaises(RedactionError):
                s.arguments('{"cmd":"echo [SECRET-1]"}', tool)

    def test_unknown_model_placeholder_blocked(self):
        with self.assertRaises(RedactionError):
            self.session.arguments('{"host":"[IP-99]"}', 'connect')

    def test_literal_placeholder_in_context_is_preserved(self):
        self.session.request({'input': 'Example: [IP-99]'})
        restored = self.session.arguments('{"example":"[IP-99]"}', 'render')
        self.assertEqual(json.loads(restored)['example'], '[IP-99]')

    def test_custom_patch_restored(self):
        result = self.session.item({'type': 'custom_tool_call', 'name': 'apply_patch', 'input': '+host=[IP-1]'})
        self.assertEqual(result['input'], '+host=11.111.111.11')

    def test_custom_code_mode_restored_conservatively(self):
        result = self.session.item({'type': 'custom_tool_call', 'name': 'exec', 'input': 'await tools.exec_command({cmd:"ping [IP-1]"})'})
        self.assertIn('11.111.111.11', result['input'])
        s = Session(Redactor())
        s.request({'input': {'password': '$(whoami)'}})
        with self.assertRaises(RedactionError):
            s.item({'type': 'custom_tool_call', 'name': 'exec', 'input': 'text("[SECRET-1]")'})

    def test_hosted_tool_in_additional_tools_is_rejected(self):
        with self.assertRaises(RedactionError):
            self.session.request({'input': [{'type': 'additional_tools', 'tools': [{'type': 'web_search'}]}]})

    def test_unknown_custom_tool_blocked(self):
        with self.assertRaises(RedactionError):
            self.session.item({'type': 'custom_tool_call', 'name': 'run_code', 'input': '[IP-1]'})

    def test_assistant_text_stays_masked(self):
        result = self.session.response({'output': [{'type': 'message', 'content': [{'text': '[IP-1]'}]}]})
        self.assertEqual(result['output'][0]['content'][0]['text'], '[IP-1]')

    def test_opaque_provider_reasoning_roundtrip(self):
        opaque = 'opaque-contents-123'
        self.session.response({'output': [{'type': 'reasoning', 'encrypted_content': opaque}]})
        safe = self.session.request({'input': [{'type': 'reasoning', 'encrypted_content': opaque}]})
        self.assertEqual(safe['input'][0]['encrypted_content'], opaque)

    def test_unknown_opaque_blocked(self):
        with self.assertRaises(RedactionError):
            self.session.request({'input': [{'type': 'reasoning', 'encrypted_content': 'untrusted'}]})

    def test_attachments_hosted_tools_and_server_state_blocked(self):
        for payload in ({'input': [{'type': 'input_image', 'image_url': 'https://example.com/img'}]}, {'input': [{'type': 'input_file', 'file_id': 'file_123'}]}, {'tools': [{'type': 'web_search'}]}, {'tools': [{'type': 'mcp'}]}, {'background': True}, {'previous_response_id': 'resp_old'}, {'conversation': 'conv_123'}):
            with self.subTest(payload=payload), self.assertRaises(RedactionError):
                self.session.request(payload)

    def test_namespaced_local_tool(self):
        self.session.request({'tools': [{'type': 'namespace', 'name': 'tools', 'tools': [{'type': 'function', 'name': 'exec_command'}]}]})

    def test_delta_splits_at_every_boundary(self):
        args = dumps({'cmd': 'printf %s [IP-1]'})
        for split in range(len(args) + 1):
            with self.subTest(split=split):
                stream = ResponseStream(self.session)
                stream.event({'type': 'response.output_item.added', 'item': {'type': 'function_call', 'id': 'fc_1', 'name': 'exec_command', 'arguments': ''}})
                emitted = []
                for part in (args[:split], args[split:]):
                    emitted += stream.event({'type': 'response.function_call_arguments.delta', 'item_id': 'fc_1', 'delta': part})
                emitted += stream.event({'type': 'response.function_call_arguments.done', 'item_id': 'fc_1', 'arguments': args})
                joined = ''.join(e['delta'] for e in emitted if e['type'].endswith('.delta'))
                self.assertEqual(json.loads(joined)['cmd'], 'printf %s 11.111.111.11')

    def test_interleaved_tool_calls(self):
        stream = ResponseStream(self.session)
        for i in (1, 2):
            stream.event({'type': 'response.output_item.added', 'item': {'type': 'function_call', 'id': f'fc_{i}', 'name': 'connect', 'arguments': ''}})
            stream.event({'type': 'response.function_call_arguments.delta', 'item_id': f'fc_{i}', 'delta': '{"host":"[IP-'})
        for i in (2, 1):
            stream.event({'type': 'response.function_call_arguments.delta', 'item_id': f'fc_{i}', 'delta': '1]"}'})
            result = stream.event({'type': 'response.function_call_arguments.done', 'item_id': f'fc_{i}', 'arguments': '{"host":"[IP-1]"}'})
            self.assertEqual(json.loads(result[-1]['arguments'])['host'], '11.111.111.11')

    def test_multiline_sse_and_terminal(self):
        wire = b'event: response.completed\r\ndata: {"type":\r\ndata: "response.completed","response":{"output":[]}}\r\n\r\n'
        frames = list(ResponseStream(self.session).frames(io.BytesIO(wire)))
        self.assertIn(b'response.completed', b''.join(frames))

    def test_incomplete_and_malformed_streams_rejected(self):
        for wire in (b'data: {broken}\n\n', b'data: {"type":"response.created"}\n\n', b'data: {"type":"response.completed"}'):
            with self.subTest(wire=wire), self.assertRaises(RedactionError):
                list(ResponseStream(self.session).frames(io.BytesIO(wire)))

    def test_response_tool_output_and_replay_are_masked_again(self):
        call = self.session.item({'type': 'function_call', 'name': 'exec_command', 'arguments': '{"cmd":"ping [IP-1]"}'})
        replay = self.session.request({'input': [call, {'type': 'function_call_output', 'output': 'Connected to 11.111.111.11'}]})
        self.assertNotIn('11.111.111.11', dumps(replay))
        self.assertIn('[IP-1]', dumps(replay))


if __name__ == '__main__':
    unittest.main()
