use sanctum::{
    MAX_EVENT, json,
    protocol::{ResponseStream, Session},
    redaction::{Policy, Redactor, restore_mapping},
};
use serde_json::{Value, json as value};

fn engine() -> Redactor {
    Redactor::new(Policy::default()).unwrap()
}
fn session() -> Session {
    let mut s = Session::new(engine());
    s.request(&value!({"input":"11.111.111.11 demo@example.com"}))
        .unwrap();
    s
}

#[test]
fn roundtrip_and_repeated_entities() {
    let mut r = engine();
    let original = "11.111.111.11 demo@example.com password=synthetic-only 11.111.111.11";
    let masked = r.text(original).unwrap();
    assert_eq!(masked.matches("[IP-1]").count(), 2);
    for secret in ["11.111.111.11", "demo@example.com", "synthetic-only"] {
        assert!(!masked.contains(secret));
    }
    assert_eq!(r.restore(&masked), original);
    assert_eq!(r.text(&masked).unwrap(), masked);
}

#[test]
fn email_followed_by_sentence_punctuation_is_still_masked() {
    for text in [
        "Contact demo@example.com.",
        "(demo@example.com)",
        "Адрес пользователь@пример.рф,",
    ] {
        let mut r = engine();
        let safe = r.text(text).unwrap();
        assert!(safe.contains("[EMAIL-1]"));
        assert!(!safe.contains('@'));
        assert_eq!(r.restore(&safe), text);
    }
}
#[test]
fn ipv6_scopes_punctuation_and_non_addresses() {
    for original in [
        "::1",
        "2001:db8::1",
        "fe80::1%eth0",
        "::ffff:192.0.2.1",
        "11.111.111.11.",
        "2001:db8::1.",
    ] {
        let mut r = engine();
        let safe = r.text(original).unwrap();
        assert!(safe.contains("[IP-1]"), "{original}: {safe}");
        assert_eq!(r.restore(&safe), original);
    }
    for text in ["999.1.1.1", "v1.2.3", "v1.2.3.4", "1.2.3.4.5"] {
        assert_eq!(engine().text(text).unwrap(), text);
    }
}
#[test]
fn unicode_quoted_and_unquoted_secrets() {
    for (text, original) in [
        ("пароль='длинный пароль'", "длинный пароль"),
        ("token=example-token", "example-token"),
        ("AWS_SECRET_ACCESS_KEY=example-value", "example-value"),
        (r#"password="embedded\"quote""#, r#"embedded\"quote"#),
    ] {
        let mut r = engine();
        let safe = r.text(text).unwrap();
        assert!(!safe.contains(original), "{safe}");
        assert_eq!(r.restore(&safe), text);
    }
}
#[test]
fn provider_key_jwt_and_pem_signatures() {
    for text in [
        format!("sk-proj-{}", "a".repeat(30)),
        format!("ghp_{}", "a".repeat(30)),
        format!("AKIA{}", "A".repeat(16)),
        "eyJabc.eyJdef.signature".into(),
        "-----BEGIN RSA PRIVATE KEY-----\nDATA\n-----END RSA PRIVATE KEY-----".into(),
    ] {
        let mut r = engine();
        let safe = r.text(&text).unwrap();
        assert_ne!(safe, text);
        assert_eq!(r.restore(&safe), text);
    }
}
#[test]
fn credentials_and_overlapping_url_email() {
    let mut r = engine();
    let original =
        "Bearer synthetic-token https://synthetic-user:synthetic-password@example.com/path";
    let safe = r.text(original).unwrap();
    for part in ["synthetic-token", "synthetic-user", "synthetic-password"] {
        assert!(!safe.contains(part));
    }
    assert_eq!(r.restore(&safe), original);
}
#[test]
fn enclosing_new_password_is_not_partially_redacted() {
    for text in [
        "password=1.2.3.4-sensitive-suffix",
        "password=sensitive-prefix-1.2.3.4",
    ] {
        let mut r = engine();
        r.text("1.2.3.4").unwrap();
        let safe = r.text(text).unwrap();
        assert!(!safe.contains("sensitive"));
        assert_eq!(r.restore(&safe), text);
    }
}
#[test]
fn custom_longest_overlap_is_fully_hidden() {
    let mut r = Redactor::new(Policy {
        literals: vec!["abc".into(), "abcdef".into()],
        max_entries: 10,
        patterns: vec![],
        internal_domains: vec![],
        personal_names: vec![],
    })
    .unwrap();
    assert_eq!(r.text("abcdef").unwrap(), "[CUSTOM-1]");
}
#[test]
fn labelled_secret_hides_prior_unlabelled_occurrence() {
    let mut s = Session::new(engine());
    let safe = s
        .request(&value!({"input":["sensitive-alone",{"password":"sensitive-alone"}]}))
        .unwrap();
    assert!(!safe.to_string().contains("sensitive-alone"));
    assert!(
        !s.request(&value!({"input":"sensitive-alone"}))
            .unwrap()
            .to_string()
            .contains("sensitive-alone")
    );
}
#[test]
fn placeholders_in_documentation_are_reserved_before_new_tokens() {
    let mut s = Session::new(engine());
    let safe = s
        .request(&value!({"input":["1.2.3.4", "Example: [IP-1]"]}))
        .unwrap();
    assert_eq!(safe["input"][0], "[IP-2]");
    assert_eq!(safe["input"][1], "Example: [IP-1]");
    assert_eq!(
        s.arguments(r#"{"example":"[IP-1]"}"#, "render").unwrap(),
        r#"{"example":"[IP-1]"}"#
    );
}
#[test]
fn token_inside_password_does_not_prevent_masking() {
    let mut r = engine();
    let original = r#"password="before [IP-1] after""#;
    let safe = r.text(original).unwrap();
    assert!(!safe.contains("before"));
    assert_eq!(r.restore(&safe), original);
}
#[test]
fn serialized_json_and_numeric_secrets() {
    let mut s = Session::new(engine());
    let safe = s
        .request(&value!({"input":[{"password":123456},{"output":"{\"token\":\"hidden-value\"}"}]}))
        .unwrap();
    assert!(!safe.to_string().contains("123456"));
    assert!(!safe.to_string().contains("hidden-value"));
    assert!(json::parse(safe["input"][1]["output"].as_str().unwrap().as_bytes()).is_ok());
}
#[test]
fn duplicate_keys_in_embedded_json_fail_closed() {
    let mut s = Session::new(engine());
    assert!(
        s.request(&value!({"input":"{\"password\":\"first\",\"password\":\"second\"}"}))
            .is_err()
    );
}
#[test]
fn policies_and_capacity_reject_invalid_data() {
    for p in [
        Policy {
            literals: vec!["".into()],
            max_entries: 1,
            patterns: vec![],
            internal_domains: vec![],
            personal_names: vec![],
        },
        Policy {
            literals: vec!["[IP-1]".into()],
            max_entries: 1,
            patterns: vec![],
            internal_domains: vec![],
            personal_names: vec![],
        },
        Policy {
            literals: vec![],
            max_entries: 0,
            patterns: vec![],
            internal_domains: vec![],
            personal_names: vec![],
        },
    ] {
        assert!(Redactor::new(p).is_err());
    }
    let mut r = Redactor::new(Policy {
        literals: vec![],
        max_entries: 1,
        patterns: vec![],
        internal_domains: vec![],
        personal_names: vec![],
    })
    .unwrap();
    assert!(r.text("1.2.3.4 2.3.4.5").is_err());
}
#[test]
fn plaintext_mapping_roundtrip_and_validation() {
    let mut r = engine();
    let safe = r.text("demo@example.com").unwrap();
    assert_eq!(
        restore_mapping(&safe, &r.export()).unwrap(),
        "demo@example.com"
    );
    assert!(restore_mapping(&safe, &value!({"unrelated":"secret"})).is_err());
}
#[test]
fn arbitrary_word_is_not_claimed_detectable() {
    assert_eq!(engine().text("randomword123").unwrap(), "randomword123");
}
#[test]
fn complex_secret_is_valid_in_structured_json() {
    let mut s = Session::new(engine());
    let original = "quote\"back\\line\n$()";
    s.request(&value!({"input":{"password":original}})).unwrap();
    let args = s
        .arguments(r#"{"password":"[SECRET-1]"}"#, "database_connect")
        .unwrap();
    assert_eq!(json::parse(args.as_bytes()).unwrap()["password"], original);
}
#[test]
fn unsafe_originals_cannot_enter_shell_or_code() {
    for tool in ["exec_command", "functions.exec", "run"] {
        let mut s = Session::new(engine());
        s.request(&value!({"input":{"password":"$(touch /tmp/never)"}}))
            .unwrap();
        assert!(s.arguments(r#"{"cmd":"echo [SECRET-1]"}"#, tool).is_err());
        assert!(
            s.item(&value!({"type":"custom_tool_call","name":"exec","input":"text('[SECRET-1]')"}))
                .is_err()
        );
    }
}
#[test]
fn safe_shell_and_patch_receive_originals() {
    let s = session();
    assert_eq!(
        json::parse(
            s.arguments(r#"{"cmd":"ping [IP-1]"}"#, "exec_command")
                .unwrap()
                .as_bytes()
        )
        .unwrap()["cmd"],
        "ping 11.111.111.11"
    );
    assert_eq!(
        s.item(&value!({"type":"custom_tool_call","name":"apply_patch","input":"+host=[IP-1]"}))
            .unwrap()["input"],
        "+host=11.111.111.11"
    );
}
#[test]
fn unknown_model_tokens_and_custom_tools_are_rejected() {
    let s = session();
    assert!(s.arguments(r#"{"host":"[IP-99]"}"#, "connect").is_err());
    assert!(
        s.item(&value!({"type":"custom_tool_call","name":"unknown","input":"[IP-1]"}))
            .is_err()
    );
}
#[test]
fn assistant_text_stays_masked_and_tool_history_is_masked_again() {
    let mut s = session();
    assert_eq!(
        s.response(&value!({"output":[{"type":"message","text":"[IP-1]"}]}))
            .unwrap()["output"][0]["text"],
        "[IP-1]"
    );
    let call = s.item(&value!({"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"ping [IP-1]\"}"})).unwrap();
    let replay = s.request(&value!({"input":[call,{"type":"function_call_output","output":"Connected to 11.111.111.11"}]})).unwrap();
    assert!(!replay.to_string().contains("11.111.111.11"));
}
#[test]
fn opaque_replay_is_exact_and_session_bound() {
    let mut s = session();
    let item = value!({"type":"reasoning","encrypted_content":"opaque-provider-content-123"});
    assert!(s.request(&value!({"input":[item.clone()]})).is_err());
    s.response(&value!({"output":[item.clone()]})).unwrap();
    assert_eq!(
        s.request(&value!({"input":[item.clone()]})).unwrap()["input"][0],
        item
    );
    assert!(session().request(&value!({"input":[item]})).is_err());
}
#[test]
fn attachments_hosted_tools_and_server_state_are_rejected() {
    for payload in [
        value!({"input":[{"type":"input_image","image_url":"data:secret"}]}),
        value!({"input":[{"type":"input_file","file_id":"file123"}]}),
        value!({"tools":[{"type":"web_search"}]}),
        value!({"input":[{"type":"additional_tools","tools":[{"type":"mcp"}]}]}),
        value!({"background":true}),
        value!({"previous_response_id":"old"}),
        value!({"conversation":"old"}),
    ] {
        assert!(session().request(&payload).is_err());
    }
    assert!(session().request(&value!({"tools":[{"type":"namespace","name":"functions","tools":[{"type":"custom","name":"exec"}]}]})).is_ok());
}

fn streaming_events() -> Vec<Value> {
    vec![
        value!({"type":"response.output_item.added","item":{"type":"function_call","id":"fc_1","name":"connect","arguments":""},"sequence_number":0}),
        value!({"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"host\":\"[IP-","sequence_number":1}),
        value!({"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"1]\",\"label\":\"тест\"}","sequence_number":2}),
        value!({"type":"response.function_call_arguments.done","item_id":"fc_1","arguments":"{\"host\":\"[IP-1]\",\"label\":\"тест\"}","sequence_number":3}),
        value!({"type":"response.completed","response":{"output":[]},"sequence_number":4}),
    ]
}
#[test]
fn every_network_split_including_utf8_and_every_token_split() {
    let wire: Vec<u8> = streaming_events()
        .iter()
        .flat_map(|e| format!("data: {e}\r\n\r\n").into_bytes())
        .collect();
    for boundary in 0..=wire.len() {
        let mut s = session();
        let mut stream = ResponseStream::default();
        let mut frames = stream.feed(&mut s, &wire[..boundary], true).unwrap();
        frames.extend(stream.feed(&mut s, &wire[boundary..], true).unwrap());
        stream.finish().unwrap();
        let mut deltas = String::new();
        for frame in frames {
            let frame = String::from_utf8(frame).unwrap();
            let event = json::parse(
                frame
                    .lines()
                    .find_map(|l| l.strip_prefix("data: "))
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
            if event["type"] == "response.function_call_arguments.delta" {
                deltas.push_str(event["delta"].as_str().unwrap());
            }
        }
        let args = json::parse(deltas.as_bytes()).unwrap();
        assert_eq!(args["host"], "11.111.111.11");
        assert_eq!(args["label"], "тест");
    }
}
#[test]
fn interleaved_tool_calls_keep_their_arguments_separate() {
    let mut s = session();
    let mut stream = ResponseStream::default();
    for id in ["a", "b"] {
        stream.event(&mut s, &value!({"type":"response.output_item.added","item":{"type":"function_call","id":id,"name":"connect","arguments":""}}), true).unwrap();
        stream.event(&mut s, &value!({"type":"response.function_call_arguments.delta","item_id":id,"delta":"{\"host\":\"[IP-"}), true).unwrap();
    }
    for id in ["b", "a"] {
        let events = stream.event(&mut s, &value!({"type":"response.function_call_arguments.done","item_id":id,"arguments":"{\"host\":\"[IP-1]\"}"}), true).unwrap();
        assert_eq!(
            json::parse(
                events.last().unwrap()["arguments"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
            )
            .unwrap()["host"],
            "11.111.111.11"
        );
    }
}
#[test]
fn malformed_incomplete_and_oversized_streams_fail_closed() {
    for wire in [
        "data: {broken}\n\n",
        "data: {\"type\":\"response.created\"}\n\n",
        "data: {\"type\":\"response.completed\"}",
    ] {
        let mut stream = ResponseStream::default();
        let result = stream
            .feed(&mut session(), wire.as_bytes(), true)
            .and_then(|_| stream.finish());
        assert!(result.is_err());
    }
    let mut stream = ResponseStream::default();
    assert!(
        stream
            .feed(&mut session(), &vec![b'x'; MAX_EVENT + 1], true)
            .is_err()
    );
}
#[test]
fn multiline_sse_and_no_restore_mode() {
    let wire = b"data: {\"type\":\n data: ignored\n\n";
    assert!(
        ResponseStream::default()
            .feed(&mut session(), wire, true)
            .is_err()
    );
    let wire = b"data: {\"type\":\ndata: \"response.completed\",\"response\":{\"output\":[]}}\n\n";
    let mut decoder = ResponseStream::default();
    assert!(
        !decoder
            .feed(&mut session(), wire, false)
            .unwrap()
            .is_empty()
    );
    decoder.finish().unwrap();
}

#[test]
fn technical_tokens_are_not_mistaken_for_generated_passwords() {
    for text in [
        "что в @/tmp/claude-1000/-home-user/ChatGPT-Sanctum/3616524b/scratchpad/mention-test.env ?",
        "see @./src/claude_hook.rs and @~/notes/plan-2026.md",
        "tool id toolu_01HF1dsUv2oq63k76VKdXadF and msg_01XFDUDYJgAACzvnptvVoYEL",
        "request req_011CQZrqrWcLdSn3Hf6uX2ka failed",
        "            if !LOCAL_TOOLS.contains(&name)",
        r#"Ok(Some(value!({"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":restored}})))"#,
        r#"let name = event["tool_name"].as_str().ok_or(Error("tool_name_required"))?;"#,
        "fn mentioned_file(mention: &str, directory: Option<&std::path::Path>) -> Option<PathBuf> {",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        r#"    .join("\u{2060}")"#,
    ] {
        let mut r = engine();
        assert_eq!(r.text(text).unwrap(), text, "{text}");
    }
    for secret in [
        "Zt7#kQ9!mW2$xR4p".to_owned(),
        format!("sk_live_{}", "Hx9Qb2Kz".repeat(3)),
        "@Zt7#kQ9!mW2$xR4p".to_owned(),
    ] {
        let mut r = engine();
        assert!(r.text(&secret).unwrap().contains('['), "{secret}");
    }
}
