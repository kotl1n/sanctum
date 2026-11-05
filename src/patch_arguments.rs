use crate::{Error, Result, protocol::Session, redaction::token_matches};

pub(crate) fn restore(session: &Session, patch: &str) -> Result<String> {
    let mut result = String::new();
    for line in patch.split_inclusive('\n') {
        let (body, ending) = line.strip_suffix('\n').map_or((line, ""), |s| (s, "\n"));
        let prefix = body.chars().next().filter(|c| matches!(c, '+' | '-' | ' '));
        if prefix.is_none()
            && token_matches(body).next().is_some()
            && ![
                "*** Add File: ",
                "*** Update File: ",
                "*** Delete File: ",
                "*** Move to: ",
                "@@ ",
            ]
            .iter()
            .any(|header| body.starts_with(header))
        {
            return Err(Error("patch_structure_placeholder_unsupported"));
        }
        for token in token_matches(body) {
            if let Some(original) = session.redactor.original(token) {
                if original.contains('\r') {
                    return Err(Error("patch_carriage_return_unsupported"));
                }
                if original.contains('\n') && prefix.is_none() {
                    return Err(Error("multiline_patch_header_unsupported"));
                }
            }
        }
        let encoded = serde_json::to_string(body).map_err(|_| Error("invalid_arguments"))?;
        let restored = session.arguments(&encoded, "data")?;
        let restored: String =
            serde_json::from_str(&restored).map_err(|_| Error("invalid_arguments"))?;
        if let Some(prefix) = prefix {
            result.push_str(&restored.replace('\n', &format!("\n{prefix}")));
        } else {
            result.push_str(&restored);
        }
        result.push_str(ending);
    }
    Ok(result)
}
