use serde_json::Value;

pub const HISTORY_UNAVAILABLE: &str = "[SANCTUM-HISTORY: unverified encrypted history omitted; visible history retained. Start a new chat or restore the original local vault to recover context.]";

pub fn kind(item: &Value) -> Option<&'static str> {
    match item["type"].as_str()? {
        "reasoning" => Some("reasoning"),
        "compaction" | "compaction_summary" => Some("compaction"),
        "context_compaction" => Some("context_compaction"),
        _ => None,
    }
}

pub fn key(kind: &str, cipher: &str) -> String {
    format!("sanctum-provider-v2:{kind}:{}:{cipher}", cipher.len())
}
