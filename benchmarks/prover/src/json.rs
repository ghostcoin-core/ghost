//! A minimal JSON object writer for result records (one object per line).

use core::fmt::Write as _;

#[derive(Clone, Debug, Default)]
pub struct Object {
    fields: Vec<(String, String)>,
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl Object {
    pub fn new() -> Self {
        Self::default()
    }

    fn set(&mut self, key: &str, value: String) -> &mut Self {
        if let Some(slot) = self.fields.iter_mut().find(|(k, _)| k == key) {
            slot.1 = value;
        } else {
            self.fields.push((key.to_string(), value));
        }
        self
    }

    pub fn str(&mut self, key: &str, value: &str) -> &mut Self {
        self.set(key, quote(value))
    }

    pub fn num(&mut self, key: &str, value: u64) -> &mut Self {
        self.set(key, value.to_string())
    }

    pub fn float(&mut self, key: &str, value: f64) -> &mut Self {
        if value.is_finite() {
            self.set(key, format!("{value:.3}"))
        } else {
            self.null(key)
        }
    }

    pub fn bool(&mut self, key: &str, value: bool) -> &mut Self {
        self.set(key, value.to_string())
    }

    pub fn null(&mut self, key: &str) -> &mut Self {
        self.set(key, "null".to_string())
    }

    /// Copy every field of `other` over this object.
    pub fn extend(&mut self, other: &Self) -> &mut Self {
        for (k, v) in &other.fields {
            self.set(k, v.clone());
        }
        self
    }

    pub fn render(&self) -> String {
        let body: Vec<String> = self
            .fields
            .iter()
            .map(|(k, v)| format!("{}:{}", quote(k), v))
            .collect();
        format!("{{{}}}", body.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_escaped_fields_in_order() {
        let mut o = Object::new();
        o.str("a", "x\"y\n").num("b", 3).bool("c", false).null("d").float("e", 1.5);
        o.num("b", 4);
        assert_eq!(o.render(), r#"{"a":"x\"y\n","b":4,"c":false,"d":null,"e":1.500}"#);
    }
}
