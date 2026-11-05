#[derive(Clone)]
struct Segment {
    start: usize,
    end: usize,
    source_start: usize,
    source_end: usize,
}

fn project(map: &[Segment], start: usize, end: usize) -> Option<(usize, usize)> {
    if start >= end {
        return None;
    }
    let first = map.get(map.partition_point(|s| s.end <= start))?;
    let last = map.get(map.partition_point(|s| s.start < end).checked_sub(1)?)?;
    let from = if first.end - first.start == first.source_end - first.source_start {
        first.source_start + start - first.start
    } else {
        first.source_start
    };
    let to = if last.end - last.start == last.source_end - last.source_start {
        last.source_start + end - last.start
    } else {
        last.source_end
    };
    Some((from, to))
}

fn push(map: &mut Vec<Segment>, item: Segment) {
    if let Some(last) = map.last_mut()
        && last.end == item.start
        && last.source_end == item.source_start
        && last.end - last.start == last.source_end - last.source_start
        && item.end - item.start == item.source_end - item.source_start
    {
        last.end = item.end;
        last.source_end = item.source_end;
    } else {
        map.push(item);
    }
}

fn hex(text: &str, start: usize) -> Option<u16> {
    u16::from_str_radix(text.get(start..start + 4)?, 16).ok()
}

fn string(text: &str, quote: usize, parent: &[Segment]) -> Option<(String, Vec<Segment>, usize)> {
    let mut decoded = String::new();
    let mut map = Vec::new();
    let mut at = quote + 1;
    while at < text.len() {
        let start = at;
        let ch = text.get(at..)?.chars().next()?;
        if ch == '"' {
            return Some((decoded, map, at + 1));
        }
        let value = if ch == '\\' {
            let escape = *text.as_bytes().get(at + 1)?;
            at += 2;
            match escape {
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                b'b' => '\u{0008}',
                b'f' => '\u{000c}',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'u' => {
                    let high = hex(text, at)?;
                    at += 4;
                    let code = if (0xd800..=0xdbff).contains(&high) {
                        if text.get(at..at + 2)? != "\\u" {
                            return None;
                        }
                        let low = hex(text, at + 2)?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return None;
                        }
                        at += 6;
                        0x10000 + ((u32::from(high) - 0xd800) << 10) + u32::from(low) - 0xdc00
                    } else {
                        u32::from(high)
                    };
                    char::from_u32(code)?
                }
                _ => return None,
            }
        } else {
            at += ch.len_utf8();
            ch
        };
        let from = decoded.len();
        decoded.push(value);
        let (source_start, source_end) = project(parent, start, at)?;
        push(
            &mut map,
            Segment {
                start: from,
                end: decoded.len(),
                source_start,
                source_end,
            },
        );
    }
    None
}

pub(crate) fn ranges(
    text: &str,
    detect: impl Fn(&str) -> Vec<(usize, usize)>,
    scalar: impl Fn(&str) -> bool,
) -> Vec<(usize, usize)> {
    fn visit(
        text: &str,
        map: &[Segment],
        depth: usize,
        detect: &impl Fn(&str) -> Vec<(usize, usize)>,
        scalar: &impl Fn(&str) -> bool,
        result: &mut Vec<(usize, usize)>,
    ) {
        let structured = depth < 64
            && text.trim_start().starts_with(['{', '[', '"'])
            && crate::json::parse(text.as_bytes()).is_ok();
        let mut atoms = Vec::new();
        if structured {
            let mut at = 0;
            while at < text.len() {
                if text.as_bytes()[at] == b'"' {
                    let Some((decoded, child, end)) = string(text, at, map) else {
                        return;
                    };
                    visit(&decoded, &child, depth + 1, detect, scalar, result);
                    at = end;
                } else if text.as_bytes()[at].is_ascii_digit() || text.as_bytes()[at] == b'-' {
                    let end = text.as_bytes()[at..]
                        .iter()
                        .position(|c| !c.is_ascii_digit() && !b".eE+-".contains(c))
                        .map_or(text.len(), |offset| at + offset);
                    atoms.push((at, end));
                    if scalar(&text[at..end])
                        && let Some(span) = project(map, at, end)
                    {
                        result.push(span);
                    }
                    at = end;
                } else if matches!(text.as_bytes()[at], b't' | b'f' | b'n') {
                    let end = at
                        + match text.as_bytes()[at] {
                            b'f' => 5,
                            _ => 4,
                        };
                    atoms.push((at, end));
                    if scalar(&text[at..end])
                        && let Some(span) = project(map, at, end)
                    {
                        result.push(span);
                    }
                    at = end;
                } else {
                    at += text[at..].chars().next().unwrap().len_utf8();
                }
            }
        }
        for (start, end) in detect(text) {
            let index = atoms.partition_point(|&(_, end)| end <= start);
            if atoms
                .get(index)
                .is_some_and(|&(from, to)| from <= start && end <= to)
            {
                continue;
            }
            if let Some(span) = project(map, start, end) {
                result.push(span);
            }
        }
    }
    let mut result = Vec::new();
    let map = [Segment {
        start: 0,
        end: text.len(),
        source_start: 0,
        source_end: text.len(),
    }];
    visit(text, &map, 0, &detect, &scalar, &mut result);
    result.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in result {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}
