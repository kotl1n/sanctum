use regex::Regex;
use std::sync::OnceLock;

pub(crate) fn spans(text: &str) -> Vec<(usize, usize)> {
    static RUN: OnceLock<Regex> = OnceLock::new();
    static CUE: OnceLock<Regex> = OnceLock::new();
    let runs = RUN.get_or_init(|| Regex::new(r"\S+").unwrap());
    let cue = CUE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:password|passwd|passphrase|пароль)(?:[ \t]+(?:is|это))?[ \t]+")
            .unwrap()
    });
    let mut result = Vec::new();
    for found in runs.find_iter(text) {
        let (offset, value) = unquote(found.as_str());
        if generated(value) {
            result.push((found.start() + offset, found.start() + offset + value.len()));
        }
    }
    for found in cue.find_iter(text) {
        let tail = &text[found.end()..];
        let length = tail
            .char_indices()
            .find_map(|(offset, c)| (offset >= 1024 || matches!(c, '\n' | '\r')).then_some(offset))
            .unwrap_or(tail.len());
        let bounded_end = found.end() + length;

        if let Some(quote @ ('"' | '\'' | '`' | '«')) = tail.chars().next() {
            if quote != '«' {
                if let Some(span) = crate::assignment::value_span(
                    &text[..bounded_end],
                    found.start(),
                    found.end(),
                    "=",
                ) && !text[span.0..span.1].trim().is_empty()
                    && (span.1 < bounded_end || bounded_end == text.len())
                {
                    result.push(span);
                }
                continue;
            }
            let start = found.end() + quote.len_utf8();
            if start <= bounded_end
                && let Some(length) = text[start..bounded_end].find('»')
                && length > 0
                && length <= 1024
                && !text[start..start + length].trim().is_empty()
            {
                result.push((start, start + length));
            }
        } else if let Some(value) = runs.find(tail).filter(|m| m.start() == 0) {
            let value = value.as_str();

            if value.chars().count() >= 6
                && value.len() <= 128
                && !value.contains("://")
                && !value.contains('=')
                && (value.chars().any(|c| c.is_ascii_digit())
                    || value.chars().any(|c| "@#$%^&*_+=~".contains(c))
                    || ["qwerty", "password", "пароль"].contains(&value.to_lowercase().as_str()))
            {
                result.push((found.end(), found.end() + value.len()));
            }
        }
    }
    result
}

fn technical(value: &str) -> bool {
    // Упоминание файла в Claude Code: `@/path`, `@./path`, `@~/path`.
    let value = value
        .strip_prefix('@')
        .filter(|path| path.starts_with(['/', '.', '~']))
        .unwrap_or(value);
    let lower = value.to_ascii_lowercase();
    if crate::redaction::is_token(value.trim_end_matches([',', ';'])) {
        return true;
    }
    // Идентификаторы API Claude: `toolu_…`, `msg_…`, `req_…`.
    if ["toolu_", "srvtoolu_", "msg_", "msgbatch_", "req_"]
        .iter()
        .any(|prefix| {
            value
                .strip_prefix(prefix)
                .is_some_and(|id| id.bytes().all(|c| c.is_ascii_alphanumeric()))
        })
    {
        return true;
    }
    // Формы исходного кода: вызов метода, обобщённый тип, атрибут, escape.
    static CODE: OnceLock<Regex> = OnceLock::new();
    let code = CODE.get_or_init(|| {
        Regex::new(
            r"(?:\.|::)[A-Za-z_][A-Za-z0-9_]+\(|\b[A-Z][A-Za-z0-9]+<[&'A-Za-z_]|^#!?\[|\\u\{[0-9A-Fa-f]+\}",
        )
        .unwrap()
    });
    if code.is_match(value) {
        return true;
    }
    // Вызов функции или макроса, в том числе с отрицанием или ссылкой:
    // `!items.contains(`, `value!(`, `Ok(`.
    if let Some((name, _)) = value.split_once('(')
        && let name = name
            .trim_start_matches(['!', '&', '*'])
            .trim_end_matches('!')
        && name.len() >= 2
        && name.as_bytes()[0].is_ascii_alphabetic()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:".contains(&c))
    {
        return true;
    }
    if value.contains("://")
        || (value.starts_with(['/', '.', '~'])
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_./-".contains(&c)))
        || value.starts_with("--")
        || (value.len() >= 3
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value.as_bytes().get(1..3) == Some(b":\\"))
        || value.contains("::")
        || [".rs", ".js", ".ts", ".json", ".py", ".md"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
    {
        return true;
    }
    if value.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-') {
        return true;
    }
    if value.contains('.')
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || b".vV-+".contains(&c))
    {
        return true;
    }
    if let Some((left, _)) = value.split_once('=')
        && !left.is_empty()
        && left.bytes().all(|c| c.is_ascii_alphabetic() || c == b'_')
    {
        return true;
    }

    if (value.contains('/')
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_./-".contains(&c)))
        || (value.contains(['_', '-'])
            && (value
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(&c))
                || value
                    .bytes()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || b"_-".contains(&c))))
    {
        return true;
    }
    false
}

fn generated(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(8..=128).contains(&bytes.len()) || !value.is_ascii() || technical(value) {
        return false;
    }
    let upper = bytes.iter().any(u8::is_ascii_uppercase);
    let lower = bytes.iter().any(u8::is_ascii_lowercase);
    let digit = bytes.iter().any(u8::is_ascii_digit);
    let symbol = bytes.iter().any(u8::is_ascii_punctuation);
    if !symbol
        && (bytes
            .windows(2)
            .filter(|pair| class(pair[0]) != class(pair[1]))
            .count()
            < 8
            || digit
                && bytes
                    .iter()
                    .enumerate()
                    .filter(|(i, c)| {
                        c.is_ascii_digit() && (*i == 0 || !bytes[*i - 1].is_ascii_digit())
                    })
                    .count()
                    < 2)
    {
        return false;
    }

    if !(upper && lower && digit && symbol
        || bytes.len() >= 12
            && upper
            && lower
            && !digit
            && bytes.iter().filter(|c| c.is_ascii_punctuation()).count() >= 3
            && bytes.iter().any(|c| b"!@#$%^&*+?~|".contains(c))
        || bytes.len() >= 12 && upper && lower && digit && !symbol
        || bytes.len() >= 24
            && upper
            && lower
            && !digit
            && !symbol
            && bytes
                .windows(2)
                .filter(|pair| class(pair[0]) != class(pair[1]))
                .count()
                >= 12
        || bytes.len() >= 14 && digit && symbol && (upper || lower))
    {
        return false;
    }
    let mut counts = [0usize; 128];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    if counts.iter().filter(|&&n| n > 0).count() < 7 {
        return false;
    }
    let entropy = counts
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let probability = n as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum::<f64>();
    entropy >= if bytes.len() < 16 { 3.0 } else { 3.3 }
}

fn class(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        0
    } else if byte.is_ascii_lowercase() {
        1
    } else {
        2
    }
}

fn unquote(value: &str) -> (usize, &str) {
    let Some(first @ ('"' | '\'' | '`')) = value.chars().next() else {
        return (0, value);
    };
    let end = value.trim_end_matches([',', ';']);
    if end.len() > 1 && end.ends_with(first) {
        (1, &end[1..end.len() - 1])
    } else {
        (0, value)
    }
}
