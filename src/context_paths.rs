use serde_json::Value;

#[derive(Clone, Copy)]
pub(crate) enum Place {
    Data,
    Request,
    Items,
    Item,
    Parts,
    Part,
    Tools,
    Tool,
    Format,
    Schema,
    SchemaMap,
    Schemas,
    Reasoning,
    Text,
    TextFormat,
    Stream,
    Traces,
    Trace,
    Memories,
    Memory,
    Choice,
    ShellAction,
}
pub(crate) enum Field {
    Control,
    Walk(Place),
}

pub(crate) fn list(place: Place) -> bool {
    matches!(
        place,
        Place::Items
            | Place::Parts
            | Place::Tools
            | Place::Schemas
            | Place::Traces
            | Place::Memories
    )
}
pub(crate) fn object(place: Place, value: &Value) -> bool {
    match place {
        Place::Item => item_type(value),
        Place::Part => one(
            &value["type"],
            &[
                "input_text",
                "output_text",
                "summary_text",
                "text",
                "reasoning_text",
            ],
        ),
        Place::Tool => one(
            &value["type"],
            &["function", "custom", "namespace", "tool_search"],
        ),
        Place::Request
        | Place::Schema
        | Place::SchemaMap
        | Place::Reasoning
        | Place::Text
        | Place::TextFormat
        | Place::Format
        | Place::Trace
        | Place::Memory
        | Place::Stream
        | Place::Choice
        | Place::ShellAction => true,
        _ => false,
    }
}

pub(crate) fn array_child(place: Place) -> Place {
    match place {
        Place::Items => Place::Item,
        Place::Parts => Place::Part,
        Place::Tools => Place::Tool,
        Place::Schemas => Place::Schema,
        Place::Traces => Place::Trace,
        Place::Memories => Place::Memory,
        _ => Place::Data,
    }
}
fn one(value: &Value, options: &[&str]) -> bool {
    value.as_str().is_some_and(|s| options.contains(&s))
}
fn identifier(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        !s.is_empty()
            && s.len() <= 512
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    })
}
fn strings(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
}
fn item_type(value: &Value) -> bool {
    one(
        &value["type"],
        &[
            "message",
            "agent_message",
            "reasoning",
            "function_call",
            "custom_tool_call",
            "function_call_output",
            "custom_tool_call_output",
            "additional_tools",
            "tool_search_call",
            "tool_search_output",
            "local_shell_call",
            "compaction",
            "compaction_summary",
            "configuration_update",
            "compaction_trigger",
            "context_compaction",
            "web_search_call",
            "image_generation_call",
        ],
    ) || (value.get("type").is_none()
        && one(
            &value["role"],
            &["user", "developer", "system", "assistant", "tool"],
        ))
}

fn nullable_item(parent: &Value, key: &str) -> bool {
    let kind = parent["type"].as_str().unwrap_or("message");
    match key {
        "id" | "internal_chat_message_metadata_passthrough" => matches!(
            kind,
            "message"
                | "agent_message"
                | "reasoning"
                | "local_shell_call"
                | "function_call"
                | "function_call_output"
                | "custom_tool_call"
                | "custom_tool_call_output"
                | "tool_search_call"
                | "tool_search_output"
                | "additional_tools"
                | "web_search_call"
                | "image_generation_call"
                | "compaction"
                | "compaction_summary"
                | "context_compaction"
        ),
        "call_id" => matches!(
            kind,
            "local_shell_call" | "tool_search_call" | "tool_search_output" | "function_call_output"
        ),
        "namespace" => matches!(
            kind,
            "function_call" | "function_call_output" | "custom_tool_call"
        ),
        "name" => matches!(kind, "function_call_output" | "custom_tool_call_output"),
        "phase" => kind == "message",
        "status" => matches!(
            kind,
            "tool_search_call" | "custom_tool_call" | "web_search_call"
        ),
        "encrypted_function_args" => kind == "function_call",
        "encrypted_content" => matches!(kind, "reasoning" | "context_compaction"),
        "content" => kind == "reasoning",
        "action" => kind == "web_search_call",
        "revised_prompt" => kind == "image_generation_call",
        _ => false,
    }
}

pub(crate) fn field(place: Place, parent: &Value, key: &str, value: &Value) -> Field {
    use Field::{Control, Walk};
    use Place::*;
    match place {
        Request => match key {
            "previous_response_id" | "conversation" if value.is_null() => Control,
            "background" if value == false || value.is_null() => Control,
            "stream" | "store" | "parallel_tool_calls" | "generate" if value.is_boolean() => {
                Control
            }
            "reasoning" | "text" | "tools" | "stream_options" | "service_tier"
            | "prompt_cache_key" | "client_metadata" | "access_programs" | "max_output_tokens"
                if value.is_null() =>
            {
                Control
            }
            "max_output_tokens" if value.is_u64() => Control,
            "model"
                if value.as_str().is_some_and(|s| {
                    !s.is_empty()
                        && s.len() <= 256
                        && s.bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_.:/-".contains(&c))
                }) =>
            {
                Control
            }
            "service_tier" if one(value, &["auto", "default", "flex", "priority", "scale"]) => {
                Control
            }
            "tool_choice" if one(value, &["auto", "none", "required"]) => Control,
            "tool_choice" if value.is_object() => Walk(Choice),
            "include"
                if value.as_array().is_some_and(|a| {
                    a.iter().all(|v| {
                        one(
                            v,
                            &[
                                "reasoning.encrypted_content",
                                "message.output_text.logprobs",
                                "code_interpreter_call.outputs",
                                "computer_call_output.output.image_url",
                                "file_search_call.results",
                                "web_search_call.action.sources",
                            ],
                        )
                    })
                }) =>
            {
                Control
            }
            "reasoning" if value.is_object() => Walk(Reasoning),
            "text" if value.is_object() => Walk(Text),
            "stream_options" if value.is_object() => Walk(Stream),
            "tools" if value.is_array() => Walk(Tools),
            "input" if value.is_array() => Walk(Items),
            "traces" if value.is_array() => Walk(Traces),
            "raw_memories" if value.is_array() => Walk(Memories),
            _ => Walk(Data),
        },
        Item if item_type(parent) => match key {
            _ if value.is_null() && nullable_item(parent, key) => Control,
            "action" if parent["type"] == "local_shell_call" && value["type"] == "exec" => {
                Walk(ShellAction)
            }
            "type" => Control,
            "role" if one(value, &["user", "developer", "system", "assistant", "tool"]) => Control,
            "id" | "call_id" | "name" | "namespace" | "author" | "recipient"
                if identifier(value) =>
            {
                Control
            }
            "status"
                if one(
                    value,
                    &[
                        "completed",
                        "in_progress",
                        "incomplete",
                        "failed",
                        "pending",
                    ],
                ) =>
            {
                Control
            }
            "phase" if one(value, &["commentary", "final_answer"]) => Control,
            "execution" if one(value, &["client", "server"]) => Control,
            "content" | "output" if value.is_array() => Walk(Parts),
            "summary" if parent["type"] == "reasoning" && value.is_array() => Walk(Parts),
            "encrypted_content" if crate::opaque::kind(parent).is_some() && value.is_string() => {
                Control
            }
            "reasoning" if parent["type"] == "configuration_update" && value.is_object() => {
                Walk(Reasoning)
            }
            "tools"
                if value.is_array()
                    && (parent["type"] == "additional_tools"
                        || (parent["type"] == "tool_search_output"
                            && parent["execution"] == "client")) =>
            {
                Walk(Tools)
            }
            _ => Walk(Data),
        },
        Part if one(
            &parent["type"],
            &[
                "input_text",
                "output_text",
                "summary_text",
                "text",
                "reasoning_text",
            ],
        ) =>
        {
            if key == "type" {
                Control
            } else {
                Walk(Data)
            }
        }
        Tool if one(
            &parent["type"],
            &["function", "custom", "namespace", "tool_search"],
        ) =>
        {
            match key {
                "type" => Control,
                "strict" if parent["type"] == "function" && value.is_boolean() => Control,
                "defer_loading"
                    if one(&parent["type"], &["function", "custom"]) && value.is_boolean() =>
                {
                    Control
                }
                "name" | "namespace" if identifier(value) => Control,
                "execution" if one(value, &["client", "server"]) => Control,
                "parameters" | "input_schema"
                    if (parent["type"] == "function"
                        || (key == "parameters" && parent["type"] == "tool_search"))
                        && (value.is_object() || value.is_boolean()) =>
                {
                    Walk(Schema)
                }
                "format" if parent["type"] == "custom" && value.is_object() => Walk(Format),
                "tools" if parent["type"] == "namespace" && value.is_array() => Walk(Tools),
                _ => Walk(Data),
            }
        }
        Format => match key {
            "type" if one(value, &["text", "grammar"]) => Control,
            "syntax" | "definition" if crate::tool_grammar::is_public(parent) => Control,
            _ => Walk(Data),
        },
        Reasoning => match key {
            "effort" | "summary" | "context" if value.is_null() => Control,
            "effort" if value.is_u64() => Control,
            "effort"
                if one(
                    value,
                    &[
                        "none",
                        "minimal",
                        "low",
                        "medium",
                        "high",
                        "xhigh",
                        "max",
                        "ultra",
                        "persistent",
                    ],
                ) =>
            {
                Control
            }
            "summary" if one(value, &["auto", "concise", "detailed", "none"]) => Control,
            "context" if one(value, &["all_turns", "last_turn", "auto", "current_turn"]) => Control,
            _ => Walk(Data),
        },
        Text => match key {
            "verbosity" | "format" if value.is_null() => Control,
            "verbosity" if one(value, &["low", "medium", "high"]) => Control,
            "format" if value.is_object() => Walk(TextFormat),
            _ => Walk(Data),
        },
        TextFormat => match key {
            "strict" if parent["type"] == "json_schema" && value.is_boolean() => Control,
            "type" if one(value, &["text", "json_object", "json_schema"]) => Control,
            "name" if identifier(value) => Control,
            "schema"
                if parent["type"] == "json_schema" && (value.is_object() || value.is_boolean()) =>
            {
                Walk(Schema)
            }
            _ => Walk(Data),
        },
        Stream if key == "reasoning_summary_delivery" && one(value, &["sequential_cutoff"]) => {
            Control
        }
        Choice => match key {
            "type" if one(value, &["function", "custom", "tool_search"]) => Control,
            "name" | "namespace" if identifier(value) => Control,
            _ => Walk(Data),
        },
        Schema => match key {
            "uniqueItems" | "readOnly" | "writeOnly" | "deprecated" | "encrypted"
                if value.is_boolean() =>
            {
                Control
            }
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum"
                if value.is_number() =>
            {
                Control
            }
            "multipleOf" if value.as_f64().is_some_and(|v| v > 0.0) => Control,
            "minLength" | "maxLength" | "minItems" | "maxItems" | "minProperties"
            | "maxProperties" | "minContains" | "maxContains"
                if value.is_u64() =>
            {
                Control
            }
            "type"
                if one(
                    value,
                    &[
                        "string", "number", "integer", "object", "array", "boolean", "null",
                    ],
                ) || value.as_array().is_some_and(|a| {
                    a.iter().all(|v| {
                        one(
                            v,
                            &[
                                "string", "number", "integer", "object", "array", "boolean", "null",
                            ],
                        )
                    })
                }) =>
            {
                Control
            }
            "required" if strings(value) => Control,
            "$ref" | "$dynamicRef"
                if value.as_str().is_some_and(|s| {
                    s.starts_with('#')
                        && s.bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"#/_~-$".contains(&c))
                }) =>
            {
                Control
            }
            "$schema"
                if one(
                    value,
                    &[
                        "https://json-schema.org/draft/2020-12/schema",
                        "http://json-schema.org/draft-07/schema#",
                    ],
                ) =>
            {
                Control
            }
            "properties" | "$defs" | "definitions" | "patternProperties" | "dependentSchemas"
                if value.is_object() =>
            {
                Walk(SchemaMap)
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" if value.is_array() => Walk(Schemas),
            "items" if value.is_array() => Walk(Schemas),
            "items"
            | "additionalItems"
            | "additionalProperties"
            | "unevaluatedProperties"
            | "unevaluatedItems"
            | "contains"
            | "not"
            | "if"
            | "then"
            | "else"
            | "propertyNames"
                if value.is_object() || value.is_boolean() =>
            {
                Walk(Schema)
            }
            _ => Walk(Data),
        },
        ShellAction => match key {
            "type" if value == "exec" => Control,
            "timeout_ms" | "working_directory" | "env" | "user" if value.is_null() => Control,
            "timeout_ms" if value.is_u64() => Control,
            _ => Walk(Data),
        },
        SchemaMap => Walk(Schema),
        Trace => match key {
            "id" if identifier(value) => Control,
            "items" if value.is_array() => Walk(Items),
            _ => Walk(Data),
        },
        Memory if key == "id" && identifier(value) => Control,
        _ => Walk(Data),
    }
}

pub(crate) fn fallback_controls(source: &Value) -> serde_json::Map<String, Value> {
    let mut result = serde_json::Map::new();
    if matches!(
        field(Place::Request, source, "model", &source["model"]),
        Field::Control
    ) {
        result.insert("model".into(), source["model"].clone());
    }
    for name in ["stream", "parallel_tool_calls"] {
        if source[name].is_boolean() {
            result.insert(name.into(), source[name].clone());
        }
    }
    if let Some(value) = source
        .get("max_output_tokens")
        .filter(|v| v.is_u64() || v.is_null())
    {
        result.insert("max_output_tokens".into(), value.clone());
    }
    if let Some(settings) = source["reasoning"].as_object() {
        let mut safe = serde_json::Map::new();
        for (key, value) in settings {
            if matches!(
                field(Place::Reasoning, &source["reasoning"], key, value),
                Field::Control
            ) {
                safe.insert(key.clone(), value.clone());
            }
        }
        result.insert("reasoning".into(), Value::Object(safe));
    }
    result
}
