use crate::{Error, Result, json};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

const MAX_DEPTH: usize = 64;
const KEYWORDS: [&str; 3] = ["true", "false", "null"];
fn keyword_index(text: &str) -> Option<usize> {
    match text {
        "true" => Some(0),
        "false" => Some(1),
        "null" => Some(2),
        _ => None,
    }
}
const SECRET_NAME: &str = r"(?:password|passwd|pwd|passphrase|(?:db|database|current|new|old|confirm)[_-]?password|password[_-]?(?:confirmation|confirm)|api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|client[_-]?secret|secret[_-]?access[_-]?key|private[_-]?key|secret|пароль|токен)";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub literals: Vec<String>,
    #[serde(default = "default_capacity")]
    pub max_entries: usize,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub internal_domains: Vec<String>,
    #[serde(default)]
    pub personal_names: Vec<String>,
}
fn default_capacity() -> usize {
    10_000
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            literals: Vec::new(),
            max_entries: default_capacity(),
            patterns: Vec::new(),
            internal_domains: Vec::new(),
            personal_names: Vec::new(),
        }
    }
}
impl Drop for Policy {
    fn drop(&mut self) {
        self.literals.iter_mut().for_each(Zeroize::zeroize);
        self.personal_names.iter_mut().for_each(Zeroize::zeroize);
        self.internal_domains.iter_mut().for_each(Zeroize::zeroize);
        self.patterns.iter_mut().for_each(Zeroize::zeroize);
    }
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        if self.max_entries == 0
            || self.max_entries > 100_000
            || self.literals.len() > self.max_entries
            || self
                .literals
                .iter()
                .any(|s| s.is_empty() || detectors().token.is_match(s))
        {
            return Err(Error("invalid_policy"));
        }
        if self.patterns.len() > 64
            || self.internal_domains.len() > 1024
            || self.personal_names.len() > self.max_entries
        {
            return Err(Error("invalid_policy"));
        }
        for pattern in &self.patterns {
            if pattern.len() > 4096 || pattern.is_empty() {
                return Err(Error("invalid_pattern"));
            }
            let regex = Regex::new(pattern).map_err(|_| Error("invalid_pattern"))?;
            if regex.is_match("") {
                return Err(Error("empty_pattern"));
            }
        }
        for literal in self.personal_names.iter().chain(&self.internal_domains) {
            if literal.is_empty() || detectors().token.is_match(literal) || literal.len() > 1024 {
                return Err(Error("invalid_policy"));
            }
        }
        if self.internal_domains.iter().any(|s| {
            !s.contains('.')
                || !s
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
        }) {
            return Err(Error("invalid_domain"));
        }
        Ok(())
    }
}

struct Detectors {
    token: Regex,
    field: Regex,
    assignment: Regex,
    email: Regex,
    ipv4: Regex,
    ipv6: Regex,
    pem: Regex,
    key: Regex,
    jwt: Regex,
    bearer: Regex,
    url_auth: Regex,
    phone: Regex,
    card: Regex,
    domain: Regex,
    personal_assignment: Regex,
}
fn detectors() -> &'static Detectors {
    static INSTANCE: OnceLock<Detectors> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let re = |s: &str| Regex::new(s).expect("static detector regex");
        Detectors {
            token: re(r"\[(?:IP|EMAIL|SECRET|KEY|PRIVATE_KEY|CUSTOM|PHONE|PERSON|DOCUMENT|DOMAIN|CARD)-[1-9][0-9]*\]"),
            field: re(&format!(r"(?i)^(?:[a-z0-9]+[_-])*(?:{SECRET_NAME})$")),
            assignment: re(&format!(r#"(?i)(?:^|[^\w])(?:\w+_)?{SECRET_NAME}(?:\\*["'])?\s*(?P<separator>[:=])[ \t]*"#)),
            email: re(r"[\w.!#$%&'*+/?^`{|}~-]+@(?:[\w-]+\.)+[\w-]{2,}"),
            ipv4: re(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"),
            ipv6: re(r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*(?:%[\w.-]+)?"),
            pem: re(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
            key: re(r"(?:sk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{16,}|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{16,})"),
            jwt: re(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
            bearer: re(r"(?i)\b(?:Bearer|Basic)\s+(?P<value>[A-Za-z0-9._~+/=-]+)"),
            phone: re(r"\+[1-9][0-9 .()-]{8,24}[0-9]"),
            card: re(r"(?:[0-9][ -]?){12,18}[0-9]"),
            domain: re(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:internal|local|corp|lan)\b"),
            personal_assignment: re(r#"(?i)(?:^|[^\w])(?P<label>phone|mobile|telephone|телефон|passport|паспорт|snils|снилс|inn|инн|iban|card_number|номер_карты|full_name|customer_name|фио)["']?\s*[:=]\s*(?:"(?P<double>(?:\\.|[^"\\])*)"|'(?P<single>(?:\\.|[^'\\])*)'|(?P<bare>[^\r\n,;"'&<>}\]]+))"#),
            url_auth: re(r"(?i)\b[a-z][a-z0-9+.-]*://(?P<value>[^\s/@]+(?::[^\s/@]*)?)@"),
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Kind {
    Ip,
    Email,
    Secret,
    Key,
    PrivateKey,
    Custom,
    Phone,
    Person,
    Document,
    Domain,
    Card,
}
impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::Ip => "IP",
            Self::Email => "EMAIL",
            Self::Secret => "SECRET",
            Self::Key => "KEY",
            Self::PrivateKey => "PRIVATE_KEY",
            Self::Custom => "CUSTOM",
            Self::Phone => "PHONE",
            Self::Person => "PERSON",
            Self::Document => "DOCUMENT",
            Self::Domain => "DOMAIN",
            Self::Card => "CARD",
        }
    }
}
struct Entry {
    kind: Kind,
    original: Zeroizing<String>,
    token: String,
}
#[derive(Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
    kind: Kind,
    priority: u8,
}

pub struct Redactor {
    provider_opaque: HashSet<String>,
    policy: Policy,
    entries: Vec<Entry>,
    by_token: HashMap<String, usize>,
    numeric_entities: HashMap<[u8; 32], usize>,
    numeric_literals: HashSet<[u8; 32]>,
    keyword_entities: [Option<usize>; 3],
    keyword_literals: [bool; 3],
    reserved: HashSet<String>,
    counts: HashMap<Kind, usize>,
    patterns: Vec<Regex>,
    domains: Option<Regex>,
}
impl Redactor {
    pub fn new(policy: Policy) -> Result<Self> {
        policy.validate()?;
        let mut numeric_literals = HashSet::new();
        for literal in &policy.literals {
            if let Some(key) = crate::numeric::fingerprint(literal) {
                numeric_literals.insert(key);
            }
        }
        let patterns = policy
            .patterns
            .iter()
            .map(|s| Regex::new(s).map_err(|_| Error("invalid_pattern")))
            .collect::<Result<Vec<_>>>()?;
        let domains = if policy.internal_domains.is_empty() {
            None
        } else {
            Some(
                Regex::new(&format!(
                    r"(?i)\b(?:[a-z0-9-]+\.)*(?:{})\b",
                    policy
                        .internal_domains
                        .iter()
                        .map(|s| regex::escape(s))
                        .collect::<Vec<_>>()
                        .join("|")
                ))
                .map_err(|_| Error("invalid_domain"))?,
            )
        };
        let keyword_literals = KEYWORDS.map(|word| policy.literals.iter().any(|s| s == word));
        Ok(Self {
            provider_opaque: HashSet::new(),
            patterns,
            domains,
            policy,
            entries: Vec::new(),
            by_token: HashMap::new(),
            numeric_entities: HashMap::new(),
            numeric_literals,
            keyword_entities: [None; 3],
            keyword_literals,
            reserved: HashSet::new(),
            counts: HashMap::new(),
        })
    }
    pub fn add_literal(&mut self, literal: &str) -> Result<()> {
        if !self.policy.literals.iter().any(|x| x == literal) {
            if literal.is_empty()
                || detectors().token.is_match(literal)
                || self.policy.literals.len() >= self.policy.max_entries
            {
                return Err(Error("credential_capacity"));
            }
            self.policy.literals.push(literal.into());
            if let Some(index) = keyword_index(literal) {
                self.keyword_literals[index] = true;
            }
            if let Some(key) = crate::numeric::fingerprint(literal) {
                self.numeric_literals.insert(key);
            }
        }
        Ok(())
    }
    pub fn reserve(&mut self, value: &Value) -> Result<()> {
        self.reserve_inner(value, 0)
    }
    fn reserve_inner(&mut self, value: &Value, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error("nesting_limit"));
        }
        match value {
            Value::String(text) => {
                self.reserve_text(text)?;
                if let Some(nested) = nested_json(text)? {
                    self.reserve_inner(&nested, depth + 1)?;
                }
            }
            Value::Object(map) => {
                for (key, item) in map {
                    self.reserve_inner(&Value::String(key.clone()), depth + 1)?;
                    self.reserve_inner(item, depth + 1)?;
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.reserve_inner(item, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn reserve_text(&mut self, text: &str) -> Result<()> {
        for m in detectors().token.find_iter(text) {
            if !self.by_token.contains_key(m.as_str()) {
                self.reserved.insert(m.as_str().into());
                if self.reserved.len() > self.policy.max_entries {
                    return Err(Error("placeholder_capacity"));
                }
            }
        }
        Ok(())
    }
    fn token(&mut self, kind: Kind, original: &str) -> Result<String> {
        if let Some(entry) = self
            .entries
            .iter()
            .find(|e| e.kind == kind && e.original.as_str() == original)
        {
            return Ok(entry.token.clone());
        }
        if self.entries.len() >= self.policy.max_entries {
            return Err(Error("vault_capacity"));
        }
        let counter = self.counts.entry(kind).or_default();
        let token = loop {
            *counter += 1;
            let candidate = format!("[{}-{}]", kind.label(), counter);
            if !self.reserved.contains(&candidate) {
                break candidate;
            }
        };
        self.by_token.insert(token.clone(), self.entries.len());
        if let Some(key) = crate::numeric::fingerprint(original) {
            self.numeric_entities
                .entry(key)
                .or_insert(self.entries.len());
        }
        if let Some(index) = keyword_index(original) {
            self.keyword_entities[index].get_or_insert(self.entries.len());
        }
        self.entries.push(Entry {
            kind,
            original: Zeroizing::new(original.into()),
            token: token.clone(),
        });
        Ok(token)
    }
    fn numeric_token(&mut self, text: &str) -> Result<Option<String>> {
        let Some(key) = crate::numeric::fingerprint(text) else {
            return Ok(None);
        };
        if let Some(&index) = self.numeric_entities.get(&key) {
            return self.token(self.entries[index].kind, text).map(Some);
        }
        if self.numeric_literals.contains(&key) {
            return self.token(Kind::Custom, text).map(Some);
        }
        Ok(None)
    }
    fn keyword_token(&mut self, text: &str) -> Result<Option<String>> {
        let Some(index) = keyword_index(text) else {
            return Ok(None);
        };
        if let Some(entry) = self.keyword_entities[index] {
            return self.token(self.entries[entry].kind, text).map(Some);
        }
        if self.keyword_literals[index]
            || self
                .patterns
                .iter()
                .any(|p| p.find(text).is_some_and(|m| !m.is_empty()))
        {
            return self.token(Kind::Custom, text).map(Some);
        }
        Ok(None)
    }
    fn spans(&self, text: &str) -> Vec<Span> {
        let d = detectors();
        let mut candidates = Vec::new();
        for (start, end) in crate::passwords::spans(text) {
            candidates.push(Span {
                start,
                end,
                kind: Kind::Secret,
                priority: 5,
            });
        }
        for (kind, original) in self
            .entries
            .iter()
            .map(|e| (e.kind, e.original.as_str()))
            .chain(
                self.policy
                    .literals
                    .iter()
                    .map(|s| (Kind::Custom, s.as_str())),
            )
        {
            for (start, _) in text.match_indices(original) {
                candidates.push(Span {
                    start,
                    end: start + original.len(),
                    kind,
                    priority: 0,
                });
            }
        }
        for original in &self.policy.personal_names {
            for (start, _) in text.match_indices(original) {
                if boundary_word(text, start, start + original.len(), false) {
                    candidates.push(Span {
                        start,
                        end: start + original.len(),
                        kind: Kind::Person,
                        priority: 1,
                    });
                }
            }
        }
        for pattern in &self.patterns {
            for m in pattern.find_iter(text).filter(|m| !m.is_empty()) {
                candidates.push(Span {
                    start: m.start(),
                    end: m.end(),
                    kind: Kind::Custom,
                    priority: 1,
                });
            }
        }
        for captures in d.personal_assignment.captures_iter(text) {
            if let Some(m) = ["double", "single", "bare"]
                .iter()
                .find_map(|n| captures.name(n))
            {
                let value = m.as_str().trim_end();
                if !value.is_empty() {
                    candidates.push(Span {
                        start: m.start(),
                        end: m.start() + value.len(),
                        kind: field_kind(&captures["label"]).unwrap_or(Kind::Document),
                        priority: 2,
                    });
                }
            }
        }
        for m in d.phone.find_iter(text) {
            let digits = m.as_str().bytes().filter(u8::is_ascii_digit).count();
            if (10..=15).contains(&digits) && boundary_word(text, m.start(), m.end(), false) {
                candidates.push(Span {
                    start: m.start(),
                    end: m.end(),
                    kind: Kind::Phone,
                    priority: 3,
                });
            }
        }
        for m in d.card.find_iter(text) {
            if valid_card(m.as_str()) && boundary_word(text, m.start(), m.end(), false) {
                candidates.push(Span {
                    start: m.start(),
                    end: m.end(),
                    kind: Kind::Card,
                    priority: 3,
                });
            }
        }
        for pattern in std::iter::once(&d.domain).chain(self.domains.iter()) {
            for m in pattern.find_iter(text) {
                if boundary_word(text, m.start(), m.end(), true)
                    && !text[m.end()..].starts_with('.')
                {
                    candidates.push(Span {
                        start: m.start(),
                        end: m.end(),
                        kind: Kind::Domain,
                        priority: 3,
                    });
                }
            }
        }
        for (pattern, kind, priority) in [
            (&d.pem, Kind::PrivateKey, 0),
            (&d.key, Kind::Key, 1),
            (&d.jwt, Kind::Secret, 1),
            (&d.email, Kind::Email, 3),
        ] {
            for m in pattern.find_iter(text) {
                if boundary_word(text, m.start(), m.end(), kind == Kind::Email) {
                    candidates.push(Span {
                        start: m.start(),
                        end: m.end(),
                        kind,
                        priority,
                    });
                }
            }
        }
        let mut assigned_until = 0;
        for captures in d.assignment.captures_iter(text) {
            if let Some(head) = captures.get(0)
                && head.start() >= assigned_until
                && let Some((start, end)) = crate::assignment::value_span(
                    text,
                    head.start(),
                    head.end(),
                    captures.name("separator").map_or("", |m| m.as_str()),
                )
            {
                assigned_until = end;
                candidates.push(Span {
                    start,
                    end,
                    kind: Kind::Secret,
                    priority: 2,
                });
            }
        }
        for pattern in [&d.bearer, &d.url_auth] {
            for c in pattern.captures_iter(text) {
                if let Some(m) = c.name("value") {
                    candidates.push(Span {
                        start: m.start(),
                        end: m.end(),
                        kind: Kind::Secret,
                        priority: 2,
                    });
                }
            }
        }
        for pattern in [&d.ipv4, &d.ipv6] {
            for m in pattern.find_iter(text) {
                let candidate = m.as_str().trim_end_matches('.');
                let end = m.start() + candidate.len();
                let address = candidate.split('%').next().unwrap_or("");
                if address.parse::<IpAddr>().is_ok() && boundary_ip(text, m.start(), end) {
                    candidates.push(Span {
                        start: m.start(),
                        end,
                        kind: Kind::Ip,
                        priority: 4,
                    });
                }
            }
        }
        candidates.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end), s.priority));
        let mut accepted: Vec<Span> = Vec::new();
        for candidate in candidates {
            if let Some(previous) = accepted.last_mut()
                && candidate.start < previous.end
            {
                if candidate.end > previous.end {
                    if candidate.priority < previous.priority {
                        previous.kind = candidate.kind;
                        previous.priority = candidate.priority;
                    }
                    previous.end = candidate.end;
                }
                continue;
            }
            accepted.push(candidate);
        }
        accepted
    }
    pub fn text(&mut self, text: &str) -> Result<String> {
        self.reserve_text(text)?;
        let spans = self.spans(text);
        let token_spans: Vec<_> = detectors()
            .token
            .find_iter(text)
            .map(|m| (m.start(), m.end()))
            .collect();
        let mut result = String::with_capacity(text.len());
        let mut cursor = 0;
        for span in spans {
            if token_spans
                .iter()
                .any(|&(s, e)| s <= span.start && span.end <= e)
            {
                continue;
            }
            result.push_str(&text[cursor..span.start]);
            result.push_str(&self.token(span.kind, &text[span.start..span.end])?);
            cursor = span.end;
        }
        result.push_str(&text[cursor..]);
        Ok(result)
    }
    pub fn value(&mut self, value: &Value) -> Result<Value> {
        self.value_inner(value, None, 0, false)
    }
    fn value_inner(
        &mut self,
        value: &Value,
        field: Option<&str>,
        depth: usize,
        key_source: bool,
    ) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(Error("nesting_limit"));
        }
        let kind = field.and_then(field_kind);
        match value {
            Value::String(text) => {
                if let Some(kind) = kind
                    && !text.is_empty()
                    && !is_token(text)
                {
                    return Ok(Value::String(self.token(kind, text)?));
                }
                if let Some(token) = self.numeric_token(text)? {
                    return Ok(Value::String(token));
                }
                if let Some(mut nested) = nested_json(text)? {
                    let raw = if key_source || nested.is_string() {
                        let raw = self.text(text)?;
                        if raw != *text {
                            if is_token(&raw) {
                                return Ok(Value::String(raw));
                            }

                            nested = match nested_json(&raw) {
                                Ok(Some(value)) => value,

                                _ => return Ok(Value::String(self.token(Kind::Secret, text)?)),
                            };
                        }
                        Some(raw)
                    } else {
                        None
                    };
                    let masked = self.value_inner(&nested, None, depth + 1, false)?;
                    if let Some(raw) = raw {
                        if masked == nested {
                            return Ok(Value::String(raw));
                        }
                        let encoded =
                            serde_json::to_string(&masked).map_err(|_| Error("invalid_json"))?;
                        return Ok(Value::String(self.text(&encoded)?));
                    }
                    return Ok(Value::String(
                        serde_json::to_string(&masked).map_err(|_| Error("invalid_json"))?,
                    ));
                }
                Ok(Value::String(self.text(text)?))
            }
            Value::Number(n) if kind.is_some() => {
                Ok(Value::String(self.token(kind.unwrap(), &n.to_string())?))
            }
            Value::Number(n) => {
                let text = n.to_string();
                if let Some(token) = self.numeric_token(&text)? {
                    return Ok(Value::String(token));
                }

                let kind = if self
                    .patterns
                    .iter()
                    .any(|p| p.find(&text).is_some_and(|m| !m.is_empty()))
                {
                    Some(Kind::Custom)
                } else if detectors().card.is_match(&text)
                    && valid_card(&text)
                    && text.bytes().all(|b| b.is_ascii_digit())
                {
                    Some(Kind::Card)
                } else {
                    None
                };
                match kind {
                    Some(kind) => Ok(Value::String(self.token(kind, &text)?)),
                    None => Ok(value.clone()),
                }
            }
            Value::Bool(_) | Value::Null => {
                let text = value.to_string();

                if value.is_boolean()
                    && let Some(kind) = field.and_then(boolean_field_kind)
                {
                    return Ok(Value::String(self.token(kind, &text)?));
                }
                match self.keyword_token(&text)? {
                    Some(token) => Ok(Value::String(token)),
                    None => Ok(value.clone()),
                }
            }
            Value::Array(items) => items
                .iter()
                .map(|v| self.value_inner(v, field, depth + 1, false))
                .collect::<Result<Vec<_>>>()
                .map(Value::Array),
            Value::Object(map) => {
                let mut result = Map::new();
                for (key, item) in map {
                    let safe_key = self
                        .value_inner(&Value::String(key.clone()), None, depth + 1, true)?
                        .as_str()
                        .ok_or(Error("invalid_masked_key"))?
                        .to_owned();
                    if result.contains_key(&safe_key) {
                        return Err(Error("key_collision"));
                    }
                    result.insert(
                        safe_key,
                        self.value_inner(item, Some(key), depth + 1, false)?,
                    );
                }
                Ok(Value::Object(result))
            }
        }
    }
    pub fn restore(&self, text: &str) -> String {
        detectors()
            .token
            .replace_all(text, |captures: &regex::Captures| {
                self.original(&captures[0])
                    .unwrap_or(&captures[0])
                    .to_owned()
            })
            .into_owned()
    }
    pub fn original(&self, token: &str) -> Option<&str> {
        self.by_token
            .get(token)
            .map(|&i| self.entries[i].original.as_str())
    }
    pub fn literal_token(&self, token: &str) -> bool {
        self.reserved.contains(token)
    }

    pub fn visual_ranges_utf16(&self, text: &str) -> Vec<(usize, usize)> {
        let spans = crate::visual_json::ranges(
            text,
            |source| {
                if crate::numeric::fingerprint(source)
                    .is_some_and(|key| self.numeric_entities.contains_key(&key))
                {
                    return vec![(0, source.len())];
                }
                let tokens: Vec<_> = detectors()
                    .token
                    .find_iter(source)
                    .map(|m| (m.start(), m.end()))
                    .collect();
                self.spans(source)
                    .into_iter()
                    .filter(|span| {
                        !tokens
                            .iter()
                            .any(|&(start, end)| start <= span.start && span.end <= end)
                            && self.entries.iter().any(|entry| {
                                entry.kind == span.kind
                                    && entry.original.as_str() == &source[span.start..span.end]
                            })
                    })
                    .map(|span| (span.start, span.end))
                    .collect()
            },
            |source| {
                crate::numeric::fingerprint(source)
                    .is_some_and(|key| self.numeric_entities.contains_key(&key))
                    || keyword_index(source).is_some_and(|i| self.keyword_entities[i].is_some())
            },
        );
        let mut result = Vec::new();
        let (mut byte_cursor, mut utf16_cursor) = (0, 0);
        for (from, to) in spans {
            utf16_cursor += text[byte_cursor..from].encode_utf16().count();
            let start = utf16_cursor;
            utf16_cursor += text[from..to].encode_utf16().count();
            result.push((start, utf16_cursor));
            byte_cursor = to;
        }
        result
    }
    pub fn has_secrets(&self) -> bool {
        !self.entries.is_empty()
    }

    pub fn finding_counts(&self) -> Vec<(&'static str, usize)> {
        [
            Kind::Ip,
            Kind::Email,
            Kind::Secret,
            Kind::Key,
            Kind::PrivateKey,
            Kind::Custom,
            Kind::Phone,
            Kind::Person,
            Kind::Document,
            Kind::Domain,
            Kind::Card,
        ]
        .into_iter()
        .filter_map(|kind| {
            let count = self
                .entries
                .iter()
                .filter(|entry| entry.kind == kind)
                .count();
            (count > 0).then_some((kind.label(), count))
        })
        .collect()
    }
    pub fn snapshot(&self) -> Value {
        serde_json::json!({"entries":self.export(),"reserved":self.reserved,"provider_opaque":self.provider_opaque})
    }
    pub fn remember_provider_opaque(&mut self, text: &str) -> Result<()> {
        let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
        if !self.provider_opaque.contains(&digest) && self.provider_opaque.len() >= 10_000 {
            return Err(Error("opaque_capacity"));
        }
        self.provider_opaque.insert(digest);
        Ok(())
    }
    pub fn known_provider_opaque(&self, text: &str) -> bool {
        self.provider_opaque
            .contains(&format!("{:x}", Sha256::digest(text.as_bytes())))
    }
    pub fn from_snapshot(policy: Policy, snapshot: &Value) -> Result<Self> {
        let mut engine = Self::new(policy)?;
        if let Some(hashes) = snapshot.get("provider_opaque") {
            let hashes = hashes.as_array().ok_or(Error("invalid_snapshot"))?;
            if hashes.len() > 10_000 {
                return Err(Error("opaque_capacity"));
            }
            for hash in hashes {
                let hash = hash
                    .as_str()
                    .filter(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()))
                    .ok_or(Error("invalid_snapshot"))?;
                engine.provider_opaque.insert(hash.into());
            }
        }
        let entries = snapshot
            .get("entries")
            .and_then(Value::as_object)
            .ok_or(Error("invalid_snapshot"))?;
        let reserved = snapshot
            .get("reserved")
            .and_then(Value::as_array)
            .ok_or(Error("invalid_snapshot"))?;
        if entries.len() > engine.policy.max_entries || reserved.len() > engine.policy.max_entries {
            return Err(Error("vault_capacity"));
        }
        for item in reserved {
            let token = item
                .as_str()
                .filter(|s| is_token(s))
                .ok_or(Error("invalid_snapshot"))?;
            engine.reserved.insert(token.into());
        }
        for (token, value) in entries {
            if !is_token(token) || engine.reserved.contains(token) {
                return Err(Error("invalid_snapshot"));
            }
            let (label, index) = token[1..token.len() - 1]
                .rsplit_once('-')
                .ok_or(Error("invalid_snapshot"))?;
            let index = index
                .parse::<usize>()
                .map_err(|_| Error("invalid_snapshot"))?;
            if index > 1_000_000 {
                return Err(Error("invalid_snapshot"));
            }
            let kind = match label {
                "IP" => Kind::Ip,
                "EMAIL" => Kind::Email,
                "SECRET" => Kind::Secret,
                "KEY" => Kind::Key,
                "PRIVATE_KEY" => Kind::PrivateKey,
                "CUSTOM" => Kind::Custom,
                "PHONE" => Kind::Phone,
                "PERSON" => Kind::Person,
                "DOCUMENT" => Kind::Document,
                "DOMAIN" => Kind::Domain,
                "CARD" => Kind::Card,
                _ => return Err(Error("invalid_snapshot")),
            };
            let original = value
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or(Error("invalid_snapshot"))?;
            engine
                .counts
                .entry(kind)
                .and_modify(|n| *n = (*n).max(index))
                .or_insert(index);
            engine.by_token.insert(token.clone(), engine.entries.len());
            if let Some(key) = crate::numeric::fingerprint(original) {
                engine
                    .numeric_entities
                    .entry(key)
                    .or_insert(engine.entries.len());
            }
            if let Some(index) = keyword_index(original) {
                engine.keyword_entities[index].get_or_insert(engine.entries.len());
            }
            engine.entries.push(Entry {
                kind,
                original: Zeroizing::new(original.into()),
                token: token.clone(),
            });
        }
        Ok(engine)
    }
    pub fn export(&self) -> Value {
        Value::Object(
            self.entries
                .iter()
                .map(|e| (e.token.clone(), Value::String(e.original.to_string())))
                .collect(),
        )
    }
}

fn nested_json(text: &str) -> Result<Option<Value>> {
    if !text.trim_start().starts_with(['{', '[', '"']) {
        return Ok(None);
    }
    match json::parse(text.as_bytes()) {
        Ok(value @ (Value::Array(_) | Value::Object(_) | Value::String(_))) => Ok(Some(value)),

        Err(_) if serde_json::from_str::<Value>(text).is_ok() => {
            Err(Error("ambiguous_embedded_json"))
        }
        _ => Ok(None),
    }
}
fn boundary_word(text: &str, start: usize, end: usize, email: bool) -> bool {
    let forbidden_before =
        |c: char| c.is_alphanumeric() || c == '_' || c == '-' || (email && ".+".contains(c));
    let forbidden_after = |c: char| c.is_alphanumeric() || c == '_' || c == '-';
    !text[..start]
        .chars()
        .next_back()
        .is_some_and(forbidden_before)
        && !text[end..].chars().next().is_some_and(forbidden_after)
}
fn boundary_ip(text: &str, start: usize, end: usize) -> bool {
    if text[..start]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.')
    {
        return false;
    }
    let mut tail = text[end..].chars();
    match tail.next() {
        Some('.') => !tail.next().is_some_and(|c| c.is_ascii_digit()),
        Some(c) => !c.is_alphanumeric() && c != '_',
        None => true,
    }
}
pub fn is_token(s: &str) -> bool {
    detectors()
        .token
        .find(s)
        .is_some_and(|m| m.start() == 0 && m.end() == s.len())
}
pub fn token_matches(text: &str) -> impl Iterator<Item = &str> {
    detectors().token.find_iter(text).map(|m| m.as_str())
}
pub fn restore_mapping(text: &str, mapping: &Value) -> Result<String> {
    let map = mapping.as_object().ok_or(Error("invalid_vault"))?;
    if map.iter().any(|(k, v)| !is_token(k) || !v.is_string()) {
        return Err(Error("invalid_vault"));
    }
    Ok(detectors()
        .token
        .replace_all(text, |c: &regex::Captures| {
            map.get(&c[0])
                .and_then(Value::as_str)
                .unwrap_or(&c[0])
                .to_owned()
        })
        .into_owned())
}

fn boolean_field_kind(field: &str) -> Option<Kind> {
    let lower = field.to_ascii_lowercase();
    if ["has_", "has-", "is_", "is-"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return None;
    }
    match field_kind(field) {
        Some(Kind::Secret) => Some(Kind::Secret),
        _ => None,
    }
}

fn field_kind(field: &str) -> Option<Kind> {
    if detectors().field.is_match(field) {
        return Some(Kind::Secret);
    }
    match field.to_lowercase().as_str() {
        "phone" | "mobile" | "telephone" | "телефон" => Some(Kind::Phone),
        "passport" | "паспорт" | "snils" | "снилс" | "inn" | "инн" | "iban" => {
            Some(Kind::Document)
        }
        "card_number" | "номер_карты" => Some(Kind::Card),
        "full_name" | "customer_name" | "фио" => Some(Kind::Person),
        _ => None,
    }
}
fn valid_card(text: &str) -> bool {
    let digits: Vec<u8> = text
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|c| c - b'0')
        .collect();
    if !(13..=19).contains(&digits.len()) || digits.iter().all(|d| *d == digits[0]) {
        return false;
    }
    digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, d)| {
            let n = if i % 2 == 1 { d * 2 } else { *d };
            if n > 9 { n - 9 } else { n }
        } as usize)
        .sum::<usize>()
        % 10
        == 0
}
