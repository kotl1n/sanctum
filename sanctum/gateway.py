"""Authenticated loopback HTTP gateway. Only Responses and models routes."""

from __future__ import annotations

from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request

from .protocol import Session, ResponseStream, dumps, MAX_EVENT
from .redaction import Policy, Redactor, RedactionError

MAX_BODY = 8 * 1024 * 1024
SESSION_ID = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
UPSTREAMS = {
    "chatgpt": "https://chatgpt.com/backend-api/codex",
    "openai": "https://api.openai.com/v1",
}


@dataclass
class Settings:
    local_key: str = field(repr=False)
    mode: str = "chatgpt"
    policy: Policy = field(default_factory=Policy, repr=False)
    restore_tools: bool = True
    timeout: float = 120
    max_sessions: int = 128
    # Test injection is deliberately unavailable on the command line.
    test_upstream: str | None = None

    def __post_init__(self):
        if len(self.local_key) < 24 or self.mode not in UPSTREAMS:
            raise ValueError("Invalid gateway settings")
        if self.test_upstream:
            parsed = urllib.parse.urlsplit(self.test_upstream)
            if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.query or parsed.fragment:
                raise ValueError("Test upstream must use loopback HTTP")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        # Never forward a provider bearer token to a redirected host.
        return None


class Gateway(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, settings: Settings):
        if address[0] != "127.0.0.1":
            raise ValueError("Gateway must bind to 127.0.0.1")
        self.settings = settings
        self.sessions: dict[str, tuple[Session, threading.RLock]] = {}
        self.session_lock = threading.Lock()
        # Ignore environment proxy settings: provider credentials only go to the
        # fixed TLS upstream, never to an ambient HTTP debugging proxy.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        super().__init__(address, Handler)

    def session(self, session_id: str):
        if not SESSION_ID.fullmatch(session_id):
            raise RedactionError("A non-sensitive session id of 8-128 characters is required")
        with self.session_lock:
            if session_id not in self.sessions:
                if len(self.sessions) >= self.settings.max_sessions:
                    raise RedactionError("Local session capacity exceeded; restart with fresh chats")
                policy = Policy((*self.settings.policy.literals, self.settings.local_key), self.settings.policy.max_entries)
                self.sessions[session_id] = (Session(Redactor(policy)), threading.RLock())
            return self.sessions[session_id]

    def handle_error(self, request, client_address):
        # Base server tracebacks can include request/response data.
        pass


class Handler(BaseHTTPRequestHandler):
    server: Gateway
    protocol_version = "HTTP/1.1"
    server_version = "Sanctum/0.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def log_message(self, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self._error(code, "unsupported_request")

    def _json(self, status: int, payload: dict):
        data = dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def _error(self, status: int, code: str):
        self._json(status, {"error": {"type": "sanctum_error", "code": code, "message": "Sanctum blocked or could not complete this request. Request content omitted."}})

    def _authorized(self):
        keys = self.headers.get_all("X-Sanctum-Key", [])
        if len(keys) != 1 or not secrets.compare_digest(keys[0].encode(), self.server.settings.local_key.encode()):
            self._error(401, "local_auth_required")
            return False
        if self.headers.get("Origin"):
            self._error(403, "browser_requests_disabled")
            return False
        return True

    def _route(self):
        parsed = urllib.parse.urlsplit(self.path)
        prefix = "/backend-api/codex" if self.server.settings.mode == "chatgpt" else "/v1"
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise RedactionError("Invalid route")
        route = parsed.path.removeprefix(prefix)
        if parsed.path != prefix + route or route not in {"/responses", "/responses/compact", "/models"}:
            raise RedactionError("Unsupported route")
        if parsed.query:
            query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
            if route != "/models" or set(query) != {"client_version"} or len(query["client_version"]) != 1 or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", query["client_version"][0]):
                raise RedactionError("Unsupported query")
        return route, ("?" + parsed.query if parsed.query else "")

    def _headers(self):
        auth = self.headers.get_all("Authorization", [])
        if len(auth) != 1 or not auth[0].startswith("Bearer "):
            raise RedactionError("Provider bearer credential required")
        # Routing identity is deliberately outside content pseudonymization.
        headers = {"Authorization": auth[0], "Accept": "text/event-stream, application/json", "Accept-Encoding": "identity", "User-Agent": "sanctum-local/0.1"}
        for name in ("ChatGPT-Account-ID", "OpenAI-Beta", "originator", "version"):
            value = self.headers.get(name)
            if value:
                if len(value) > 512 or any(ord(c) < 32 or ord(c) > 126 for c in value):
                    raise RedactionError("Invalid routing header")
                headers[name] = value
        # The local session id is also used by the provider for routing.
        session_id = self.headers.get("session_id")
        if session_id:
            if not SESSION_ID.fullmatch(session_id):
                raise RedactionError("Invalid session header")
            headers["session_id"] = session_id
        return headers

    def do_GET(self):
        if not self._authorized():
            return
        if self.path == "/health":
            self._json(200, {"service": "sanctum", "version": "0.1.0", "mode": self.server.settings.mode, "text_only": True, "restore_tools": self.server.settings.restore_tools})
            return
        try:
            route, query = self._route()
            if route != "/models":
                raise RedactionError("Unsupported GET")
            headers = self._headers()
            self._forward("GET", route + query, headers, None, None)
        except (RedactionError, ValueError, RecursionError):
            self._error(400, "request_rejected")

    def do_POST(self):
        if not self._authorized():
            return
        try:
            route, query = self._route()
            if route == "/models" or self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding", "identity") != "identity":
                raise RedactionError("Unsupported request encoding")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not lengths[0].isdigit():
                raise RedactionError("Content-Length required")
            length = int(lengths[0])
            if not 0 < length <= MAX_BODY:
                self._error(413, "payload_too_large")
                return
            if self.headers.get_content_type() != "application/json":
                self._error(415, "json_required")
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise RedactionError("Incomplete request")
            def pairs(items):
                result = {}
                for key, value in items:
                    if key in result:
                        raise RedactionError("Duplicate JSON key")
                    result[key] = value
                return result
            payload = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(RedactionError("Non-finite JSON number")))
            if not isinstance(payload, dict):
                raise RedactionError("JSON object required")
            headers = self._headers()
            session_id = self.headers.get("session_id") or self.headers.get("X-Sanctum-Session") or payload.get("prompt_cache_key")
            if not isinstance(session_id, str):
                raise RedactionError("Session id required")
            session, lock = self.server.session(session_id)
            with lock:
                # Authorization must reach the provider as a header, but the
                # same credential must never be echoed as model context.
                bearer = headers["Authorization"][len("Bearer "):]
                policy = session.redactor.policy
                if bearer and bearer not in policy.literals:
                    if len(policy.literals) >= policy.max_entries:
                        raise RedactionError("Credential rotation capacity exceeded")
                    session.redactor.policy = Policy((*policy.literals, bearer), policy.max_entries)
                safe = session.request(payload)
                data = dumps(safe).encode()
                headers["Content-Type"] = "application/json"
                self._forward("POST", route + query, headers, data, session)
        except (RedactionError, ValueError, TypeError, UnicodeError, RecursionError):
            self._error(400, "request_rejected")
        except (OSError, TimeoutError):
            self.close_connection = True

    def _forward(self, method, route, headers, data, session):
        settings = self.server.settings
        upstream = settings.test_upstream or UPSTREAMS[settings.mode]
        request = urllib.request.Request(upstream + route, data=data, headers=headers, method=method)
        try:
            response = self.server.opener.open(request, timeout=settings.timeout)
        except urllib.error.HTTPError as exc:
            # Upstream errors sometimes echo the entire rejected input. Preserve
            # the status, never its arbitrary body, Location or Set-Cookie.
            status = exc.code
            exc.close()
            self._error(status if 400 <= status <= 599 else 502, f"upstream_http_{status}")
            return
        except (urllib.error.URLError, OSError, TimeoutError):
            self._error(502, "upstream_unavailable")
            return
        with response:
            if response.headers.get("Content-Encoding", "identity") != "identity":
                self._error(502, "unsupported_upstream_encoding")
                return
            content_type = response.headers.get_content_type()
            if content_type == "text/event-stream" and session:
                self.send_response(response.status)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                try:
                    if settings.restore_tools:
                        frames = ResponseStream(session).frames(response)
                    else:
                        # Still parse to register provider-generated opaque data.
                        frames = self._unrestored_frames(response, session)
                    for frame in frames:
                        self.wfile.write(frame)
                        self.wfile.flush()
                except (RedactionError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OSError):
                    # Never fall back to an unprocessed tool call on failure.
                    event = {"type": "error", "code": "sanctum_stream_rejected", "message": "Sanctum stopped this stream; content omitted."}
                    try:
                        self.wfile.write(f"event: error\ndata: {dumps(event)}\n\n".encode())
                    except OSError:
                        pass
                return
            if content_type != "application/json":
                self._error(502, "unsupported_upstream_content")
                return
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                self._error(502, "upstream_payload_too_large")
                return
            try:
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise ValueError()
                if session:
                    session.remember_opaque(payload)
                    if settings.restore_tools:
                        payload = session.response(payload)
                self._json(response.status, payload)
            except (RedactionError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
                self._error(502, "upstream_payload_rejected")

    def _unrestored_frames(self, response, session):
        # Reuse the bounded SSE parser with identity event transformation.
        stream = ResponseStream(session)
        def identity(event):
            session.remember_opaque(event)
            return [event]
        stream.event = identity
        return stream.frames(response)
