use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use zeroize::Zeroizing;

pub(crate) fn fingerprint(text: &str) -> Option<[u8; 32]> {
    if !text
        .as_bytes()
        .first()
        .is_some_and(|c| c.is_ascii_digit() || *c == b'-')
    {
        return None;
    }
    static NUMBER: OnceLock<Regex> = OnceLock::new();
    let grammar = NUMBER.get_or_init(|| {
        Regex::new(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$").unwrap()
    });
    if !grammar.is_match(text) {
        return None;
    }
    let (negative, unsigned) = text
        .strip_prefix('-')
        .map_or((false, text), |rest| (true, rest));
    let (mantissa, exponent) = unsigned
        .find(['e', 'E'])
        .map_or((unsigned, "0"), |at| (&unsigned[..at], &unsigned[at + 1..]));
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = Zeroizing::new(format!("{whole}{fraction}"));
    let significant = digits.trim_start_matches('0');
    let nonzero = significant.trim_end_matches('0');
    let (negative, canonical, exponent) = if nonzero.is_empty() {
        (false, "0", 0i64)
    } else {
        let exponent = exponent
            .parse::<i64>()
            .ok()?
            .checked_sub(i64::try_from(fraction.len()).ok()?)?
            .checked_add(i64::try_from(significant.len() - nonzero.len()).ok()?)?;
        (negative, nonzero, exponent)
    };
    let mut digest = Sha256::new();
    digest.update([u8::from(negative)]);
    digest.update(canonical.as_bytes());
    digest.update([0xff]);
    digest.update(exponent.to_le_bytes());
    Some(digest.finalize().into())
}
