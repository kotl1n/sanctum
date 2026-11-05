use crate::{
    Result,
    redaction::{Policy, Redactor},
};
use serde_json::{Value, json};

pub fn inspect(text: &str, policy: Result<Policy>, active: bool) -> Value {
    let operation = || -> Result<Value> {
        let mut engine = Redactor::new(policy?)?;
        let original = json!(text);
        engine.reserve(&original)?;
        let first = engine.value(&original)?;
        let masked = engine.value(&first)?;
        let findings: Vec<Value> = engine
            .finding_counts()
            .into_iter()
            .map(|(kind, count)| json!({"kind":kind,"count":count}))
            .collect();
        let total: usize = findings
            .iter()
            .filter_map(|v| v["count"].as_u64())
            .map(|n| n as usize)
            .sum();
        Ok(
            json!({"status":"ready","masked_text":masked,"findings":findings,"total":total,"spans_utf16":engine.visual_ranges_utf16(text),
                  "active":active,"persisted":false}),
        )
    };
    operation().unwrap_or_else(|_| {
        json!({"status":"unavailable","masked_text":crate::rewrite::OMITTED,
        "findings":[],"total":0,"spans_utf16":[],"active":active,"persisted":false})
    })
}
