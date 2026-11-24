use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;

/// Keep object members in wire order, including occurrences of the same key.
pub(crate) struct ObjectMembers<'a>(pub Vec<(String, &'a RawValue)>);

impl<'de> Deserialize<'de> for ObjectMembers<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;

        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = ObjectMembers<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut members = Vec::new();
                while let Some(member) = map.next_entry()? {
                    members.push(member);
                }
                Ok(ObjectMembers(members))
            }
        }

        deserializer.deserialize_map(ObjectVisitor)
    }
}

pub(crate) enum WalkError {
    InvalidJson,
    Deadline,
}

impl From<serde_json::Error> for WalkError {
    fn from(_: serde_json::Error) -> Self {
        Self::InvalidJson
    }
}

pub(crate) fn visit_strings(
    raw: &RawValue,
    field: Option<&str>,
    depth: usize,
    visit: &mut impl FnMut(&str, &str, Option<&str>) -> Result<(), WalkError>,
    check_deadline: &impl Fn() -> Result<(), WalkError>,
) -> Result<(), WalkError> {
    check_deadline()?;
    // RawValue does not apply the recursion limit of the Value deserializer.
    if depth >= 128 {
        return Err(WalkError::InvalidJson);
    }

    let token = raw.get();
    match token.as_bytes().first() {
        Some(b'"') => {
            let text: String = serde_json::from_str(token)?;
            visit(token, &text, field)?;
        }
        Some(b'[') => {
            for element in serde_json::from_str::<Vec<&RawValue>>(token)? {
                visit_strings(element, field, depth + 1, visit, check_deadline)?;
            }
        }
        Some(b'{') => {
            for (key, value) in serde_json::from_str::<ObjectMembers<'_>>(token)?.0 {
                visit_strings(value, Some(&key), depth + 1, visit, check_deadline)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Apply edits in source order without parsing or reserializing untouched tokens.
pub(crate) struct JsonEdits<'a> {
    source: &'a str,
    output: String,
    cursor: usize,
}

impl<'a> JsonEdits<'a> {
    pub fn new(source: &'a str) -> Self {
        Self {
            source,
            output: String::new(),
            cursor: 0,
        }
    }

    pub fn replace(&mut self, token: &str, replacement: &str) {
        // RawValue borrows directly from the original UTF-8 input.
        let start = token.as_ptr() as usize - self.source.as_ptr() as usize;
        self.output.push_str(&self.source[self.cursor..start]);
        self.output.push_str(replacement);
        self.cursor = start + token.len();
    }

    pub fn finish(mut self) -> Option<String> {
        if self.cursor == 0 {
            return None;
        }
        self.output.push_str(&self.source[self.cursor..]);
        Some(self.output)
    }
}
