"""Detection and reversible replacements. No network, logging, or disk writes."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import ipaddress
import json
import re
from pathlib import Path
from typing import Any


class RedactionError(ValueError):
    """A payload cannot be safely processed under the configured policy."""


TOKEN = re.compile(r"\[(?:IP|EMAIL|SECRET|KEY|PRIVATE_KEY|CUSTOM)-[1-9][0-9]*\]")
SECRET_NAME = r"(?:password|passwd|pwd|passphrase|api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|client[_-]?secret|secret[_-]?access[_-]?key|private[_-]?key|secret|пароль|токен)"
SECRET_FIELD = re.compile(r"^(?:" + SECRET_NAME + r")$", re.I)
ASSIGNMENT = re.compile(
    r"(?<![\w])(?:[\w]+_)?" + SECRET_NAME
    + r"[\"']?\s*[:=]\s*(?:\"(?P<double>(?:\\.|[^\"\\])*)\"|'(?P<single>(?:\\.|[^'\\])*)'|(?P<bare>[^\s,;\"'&<>}\]]+))",
    re.I,
)
EMAIL = re.compile(r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+@(?:[\w-]+\.)+[\w-]{2,}(?![\w-])", re.UNICODE)
IPV4 = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*(?:%[\w.-]+)?(?![\w:])")
PEM = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----")
KEY = re.compile(r"(?<![\w-])(?:sk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{16,}|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{16,})(?![\w-])")
JWT = re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![\w-])")
BEARER = re.compile(r"\b(?:Bearer|Basic)\s+(?P<value>[A-Za-z0-9._~+/=-]+)", re.I)
URL_AUTH = re.compile(r"\b[a-z][a-z0-9+.-]*://(?P<value>[^\s/@]+(?::[^\s/@]*)?)@", re.I)


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str
    priority: int


@dataclass(frozen=True)
class Policy:
    literals: tuple[str, ...] = ()
    max_entries: int = 10000

    def __post_init__(self):
        if not isinstance(self.max_entries, int) or isinstance(self.max_entries, bool) or self.max_entries < 1:
            raise RedactionError("Invalid vault capacity")
        if any(not isinstance(x, str) or not x or TOKEN.search(x) for x in self.literals):
            raise RedactionError("Invalid custom secret")

    @classmethod
    def load(cls, path: str | Path | None) -> Policy:
        if path is None:
            return cls()
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(data, dict) or set(data) - {"literals", "max_entries"}:
                raise ValueError()
            literals = data.get("literals", [])
            if not isinstance(literals, list):
                raise ValueError()
            return cls(tuple(literals), data.get("max_entries", 10000))
        except (OSError, ValueError, TypeError):
            raise RedactionError("Cannot load policy; content omitted") from None


class Redactor:
    """Use one instance per local session. Instances are not thread-safe."""

    def __init__(self, policy: Policy | None = None):
        self.policy = policy or Policy()
        self._originals: dict[str, str] = {}
        self._tokens: dict[tuple[str, str], str] = {}
        self._reserved: set[str] = set()
        self.counts: Counter[str] = Counter()

    def reserve(self, value: Any) -> None:
        """Keep literal examples of placeholders from colliding with new ones."""
        if isinstance(value, str):
            for match in TOKEN.finditer(value):
                token = match.group()
                if token not in self._originals:
                    self._reserved.add(token)
                    if len(self._reserved) > self.policy.max_entries:
                        raise RedactionError("Placeholder capacity exceeded")
            if value.lstrip().startswith(("{", "[")):
                try:
                    nested = json.loads(value)
                except (ValueError, RecursionError):
                    pass
                else:
                    if isinstance(nested, (dict, list)):
                        self.reserve(nested)
        elif isinstance(value, dict):
            for key, item in value.items():
                self.reserve(key)
                self.reserve(item)
        elif isinstance(value, list):
            for item in value:
                self.reserve(item)

    def _spans(self, text: str) -> list[Span]:
        candidates: list[Span] = []
        # Remember a discovered password even when it later appears without a
        # label in terminal output or a subsequent user message.
        for token, literal in self._originals.items():
            start = 0
            while (start := text.find(literal, start)) >= 0:
                candidates.append(Span(start, start + len(literal), token[1:token.rfind("-")], 0))
                start += len(literal)
        for literal in self.policy.literals:
            start = 0
            while (start := text.find(literal, start)) >= 0:
                candidates.append(Span(start, start + len(literal), "CUSTOM", 0))
                start += len(literal)
        for pattern, kind, priority in ((PEM, "PRIVATE_KEY", 0), (KEY, "KEY", 1), (JWT, "SECRET", 1), (EMAIL, "EMAIL", 3)):
            candidates.extend(Span(m.start(), m.end(), kind, priority) for m in pattern.finditer(text))
        for match in ASSIGNMENT.finditer(text):
            group = next(g for g in ("double", "single", "bare") if match.group(g) is not None)
            if match.group(group):
                candidates.append(Span(*match.span(group), "SECRET", 2))
        for pattern in (BEARER, URL_AUTH):
            candidates.extend(Span(*m.span("value"), "SECRET", 2) for m in pattern.finditer(text))
        for pattern in (IPV4, IPV6):
            for match in pattern.finditer(text):
                try:
                    ipaddress.ip_address(match.group())
                except ValueError:
                    continue
                candidates.append(Span(match.start(), match.end(), "IP", 4))
        # Cover the UNION of overlapping detections. Choosing a short known
        # original over a newly detected enclosing password can expose its
        # suffix. Crossing URL-auth/email detections need their full union too.
        accepted: list[Span] = []
        for candidate in sorted(candidates, key=lambda s: (s.start, -s.end, s.priority)):
            if not accepted or candidate.start >= accepted[-1].end:
                accepted.append(candidate)
                continue
            previous = accepted[-1]
            if candidate.end <= previous.end:
                continue
            chosen = previous if previous.priority <= candidate.priority else candidate
            accepted[-1] = Span(previous.start, candidate.end, chosen.kind, chosen.priority)
        return accepted

    def _token(self, kind: str, value: str) -> str:
        key = (kind, value)
        if key not in self._tokens:
            if len(self._tokens) >= self.policy.max_entries:
                raise RedactionError("Local vault capacity exceeded; request blocked")
            self.counts[kind] += 1
            token = f"[{kind}-{self.counts[kind]}]"
            while token in self._reserved:
                self.counts[kind] += 1
                token = f"[{kind}-{self.counts[kind]}]"
            self._tokens[key] = token
            self._originals[token] = value
        return self._tokens[key]

    def text(self, text: str) -> str:
        self.reserve(text)
        spans = self._spans(text)
        pieces: list[str] = []
        cursor = 0
        token_spans = [m.span() for m in TOKEN.finditer(text)]
        for span in spans:
            if any(start <= span.start and span.end <= end for start, end in token_spans):
                continue
            pieces.extend((text[cursor:span.start], self._token(span.kind, text[span.start:span.end])))
            cursor = span.end
        pieces.append(text[cursor:])
        return "".join(pieces)

    def value(self, value: Any, field: str | None = None) -> Any:
        """Sanitize every JSON string, including keys and nested tool data."""
        if isinstance(value, str):
            if field and SECRET_FIELD.fullmatch(field) and value and not TOKEN.fullmatch(value):
                return self._token("SECRET", value)
            # Tool arguments/results are often JSON serialized inside a string.
            if value.lstrip().startswith(("{", "[")):
                try:
                    nested = json.loads(value)
                except (ValueError, RecursionError):
                    pass
                else:
                    if isinstance(nested, (dict, list)):
                        return json.dumps(self.value(nested), ensure_ascii=False, separators=(",", ":"))
            return self.text(value)
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                safe_key = self.text(key)
                if safe_key in result:
                    raise RedactionError("Redacted key collision; request blocked")
                if SECRET_FIELD.fullmatch(key) and isinstance(item, (int, float)) and not isinstance(item, bool):
                    result[safe_key] = self._token("SECRET", str(item))
                else:
                    result[safe_key] = self.value(item, key)
            return result
        if isinstance(value, list):
            return [self.value(item, field) for item in value]
        return value

    def restore(self, text: str) -> str:
        """One pass: never recursively expand tokens inside an original."""
        return TOKEN.sub(lambda m: self._originals.get(m.group(), m.group()), text)

    def export(self) -> dict[str, str]:
        return dict(self._originals)

    def is_literal_token(self, token: str) -> bool:
        return token in self._reserved


def restore_with_mapping(text: str, mapping: dict[str, str]) -> str:
    if not isinstance(mapping, dict) or any(not isinstance(k, str) or not TOKEN.fullmatch(k) or not isinstance(v, str) for k, v in mapping.items()):
        raise RedactionError("Invalid vault file")
    return TOKEN.sub(lambda m: mapping.get(m.group(), m.group()), text)
