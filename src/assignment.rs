pub(crate) fn value_span(
    text: &str,
    head_start: usize,
    value_start: usize,
    separator: &str,
) -> Option<(usize, usize)> {
    let prefix = text[..head_start].rsplit('\n').next()?.trim_end();
    let declaration = [
        "let",
        "let mut",
        "const",
        "var",
        "pub",
        "pub(crate)",
        "pub(super)",
    ]
    .iter()
    .any(|word| {
        prefix.strip_suffix(word).is_some_and(|before| {
            before.is_empty() || before.chars().next_back().is_some_and(char::is_whitespace)
        })
    });
    if separator == ":" && declaration {
        let end = line_end(text, value_start);
        let equals = text[value_start..end].find('=')? + value_start;
        let start =
            equals + 1 + text[equals + 1..end].len() - text[equals + 1..end].trim_start().len();
        return value_span(text, head_start, start, "=");
    }
    let tail = &text[value_start..];
    let slashes = tail.bytes().take_while(|&byte| byte == b'\\').count();
    let quote = tail.as_bytes().get(slashes).copied();

    if (slashes == 0 || !slashes.is_multiple_of(2)) && matches!(quote, Some(b'"' | b'\'' | b'`')) {
        return quoted(text, value_start, slashes, quote?);
    }

    for marker in ["br", "rb", "fr", "rf", "r", "b", "f", "u"] {
        if let Some(rest) = tail.strip_prefix(marker) {
            let hashes = rest.bytes().take_while(|&byte| byte == b'#').count();
            if rest.as_bytes().get(hashes) == Some(&b'"') {
                if hashes == 0 {
                    return quoted(text, value_start + marker.len(), 0, b'"');
                }
                let start = value_start + marker.len() + hashes + 1;
                let delimiter = format!("\"{}", "#".repeat(hashes));
                let end = text[start..]
                    .find(&delimiter)
                    .map(|offset| start + offset)
                    .unwrap_or_else(|| line_end(text, start));
                return (end > start).then_some((start, end));
            }
        }
    }
    let end = tail
        .char_indices()
        .find_map(|(offset, c)| {
            (c.is_whitespace() || ",;\"'&<>}]".contains(c)).then_some(value_start + offset)
        })
        .unwrap_or(text.len());
    if end == value_start {
        return None;
    }
    let bare = &text[value_start..end];
    let environment_reference = [
        "os.getenv(",
        "os.environ[",
        "os.environ.get(",
        "process.env.",
        "process.env[",
        "std::env::var(",
        "std::env::var_os(",
        "env::var(",
        "env::var_os(",
    ]
    .iter()
    .any(|start| tail.starts_with(start));
    if environment_reference {
        let lookup_quotes = usize::from(!tail.starts_with("process.env."));
        let (end, fallback) = reference_end(text, value_start, lookup_quotes);
        return fallback.then_some((value_start, end));
    }
    let numeric_literal = bare.as_bytes().first().is_some_and(u8::is_ascii_digit)
        || bare
            .strip_prefix(['-', '+'])
            .is_some_and(|rest| rest.as_bytes().first().is_some_and(u8::is_ascii_digit));
    if declaration && !numeric_literal {
        return None;
    }
    Some((value_start, end))
}

fn reference_end(text: &str, start: usize, lookup_quotes: usize) -> (usize, bool) {
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut quoted_values = 0;
    let mut fallback = false;
    for (offset, c) in text[start..].char_indices() {
        if let Some(current) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == current {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => {
                quote = Some(c);
                quoted_values += 1;
            }
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth > 0 => fallback = true,
            ';' | '\r' | '\n' if depth == 0 => {
                return (start + offset, fallback || quoted_values > lookup_quotes);
            }
            _ => {}
        }
    }
    (text.len(), fallback || quoted_values > lookup_quotes)
}

fn quoted(text: &str, opening: usize, slashes: usize, quote: u8) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let quote_start = opening + slashes;
    let triple = slashes == 0
        && bytes
            .get(quote_start..quote_start + 3)
            .is_some_and(|value| value == [quote, quote, quote]);
    let width = if triple { 3 } else { 1 };
    let start = quote_start + width;
    let mut run = 0;
    for index in start..bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' {
            run += 1;
            continue;
        }

        if byte == quote
            && run >= slashes
            && (run - slashes).is_multiple_of(2 * (slashes + 1))
            && (!triple
                || bytes
                    .get(index..index + 3)
                    .is_some_and(|v| v == [quote, quote, quote]))
        {
            let end = index - slashes;
            return (end > start).then_some((start, end));
        }
        run = 0;
    }
    let end = line_end(text, start);
    (end > start).then_some((start, end))
}

fn line_end(text: &str, start: usize) -> usize {
    text[start..]
        .find(['\r', '\n'])
        .map(|end| start + end)
        .unwrap_or(text.len())
}
