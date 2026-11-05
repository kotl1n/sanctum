use crate::{Error, Result};
use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::{Map, Number, Value, value::RawValue};
use std::fmt;

struct Object(Vec<(String, Box<RawValue>)>);
impl<'de> Deserialize<'de> for Object {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = Object;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("strict JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Object, A::Error> {
                let mut values = Vec::new();
                let mut keys = std::collections::HashSet::new();
                while let Some((key, item)) = map.next_entry::<String, Box<RawValue>>()? {
                    if !keys.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    values.push((key, item));
                }
                Ok(Object(values))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

fn value(raw: &RawValue, depth: usize) -> Result<Value> {
    if depth > 128 {
        return Err(Error("invalid_json"));
    }
    let text = raw.get();
    let invalid = |_| Error("invalid_json");
    match text.as_bytes().first() {
        Some(b'{') => {
            let Object(object) = serde_json::from_str(text).map_err(invalid)?;
            let mut result = Map::new();
            for (key, item) in object {
                result.insert(key, value(&item, depth + 1)?);
            }
            Ok(Value::Object(result))
        }
        Some(b'[') => {
            let items: Vec<Box<RawValue>> = serde_json::from_str(text).map_err(invalid)?;
            items
                .iter()
                .map(|item| value(item, depth + 1))
                .collect::<Result<Vec<_>>>()
                .map(Value::Array)
        }
        Some(b'-' | b'0'..=b'9') => {
            let number: Number = serde_json::from_str(text).map_err(invalid)?;

            if !number.as_f64().is_some_and(f64::is_finite) {
                return Err(Error("invalid_json"));
            }

            Ok(Value::Number(Number::from_string_unchecked(
                text.to_owned(),
            )))
        }
        _ => serde_json::from_str(text).map_err(invalid),
    }
}

pub fn parse(bytes: &[u8]) -> Result<Value> {
    let raw: Box<RawValue> = serde_json::from_slice(bytes).map_err(|_| Error("invalid_json"))?;
    value(&raw, 0)
}
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error("invalid_json"))
}
