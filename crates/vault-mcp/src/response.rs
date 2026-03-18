//! Response formatting helpers.
//!
//! Mirrors the Python `build_response()` and `format_response()` patterns:
//! strip null/empty/default fields, serialize as compact JSON.

use serde_json::{Map, Value};
use vault_core::security::mask_value;

/// Build a response, stripping null values, empty arrays/objects, and default fields.
pub fn build_response(mut value: Value) -> Value {
    strip_defaults(&mut value);
    value
}

/// Format a response as compact JSON text.
pub fn format_response(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
}

/// Strip null values, empty arrays/objects, and known default fields.
fn strip_defaults(value: &mut Value) {
    if let Value::Object(map) = value {
        map.retain(|_, v| {
            !v.is_null()
                && !matches!(v, Value::Array(a) if a.is_empty())
                && !matches!(v, Value::Object(m) if m.is_empty())
        });

        // Remove fields matching their default values
        let defaults: &[(&str, &str)] = &[("storage_mode", "vault"), ("category", "env_var")];
        for (key, default_val) in defaults {
            if let Some(Value::String(s)) = map.get(*key) {
                if s == *default_val {
                    map.remove(*key);
                }
            }
        }

        // Recurse into nested objects/arrays
        for v in map.values_mut() {
            strip_defaults(v);
        }
    } else if let Value::Array(arr) = value {
        for v in arr.iter_mut() {
            strip_defaults(v);
        }
    }
}

/// Format a vault entry as a response-ready JSON object.
pub fn entry_to_json(entry: &vault_core::VaultEntry, include_value: bool) -> Value {
    let mut map = Map::new();
    map.insert("path".into(), Value::String(entry.path.clone()));

    if include_value {
        map.insert("value".into(), Value::String(entry.value.clone()));
    } else {
        map.insert(
            "value_preview".into(),
            Value::String(mask_value(&entry.value)),
        );
    }

    map.insert("category".into(), Value::String(entry.category.clone()));
    insert_opt_str(&mut map, "service", &entry.service);
    insert_opt_str(&mut map, "app", &entry.app);
    insert_opt_str(&mut map, "env", &entry.env);
    insert_opt_str(&mut map, "notes", &entry.notes);
    map.insert(
        "storage_mode".into(),
        Value::String(entry.storage_mode.clone()),
    );
    insert_opt_str(&mut map, "expires_at", &entry.expires_at);
    insert_opt_str(&mut map, "created_at", &entry.created_at);
    insert_opt_str(&mut map, "updated_at", &entry.updated_at);

    if !entry.tags.is_empty() {
        let arr: Vec<Value> = entry
            .tags
            .iter()
            .map(|s| Value::String(s.clone()))
            .collect();
        map.insert("tags".into(), Value::Array(arr));
    }

    if let Some(days) = entry.rotation_interval_days {
        map.insert("rotation_interval_days".into(), Value::Number(days.into()));
    }

    if !entry.related_apps.is_empty() {
        let arr: Vec<Value> = entry
            .related_apps
            .iter()
            .map(|s| Value::String(s.clone()))
            .collect();
        map.insert("related_apps".into(), Value::Array(arr));
    }

    Value::Object(map)
}

/// Format a guide as a response-ready JSON object.
pub fn guide_to_json(guide: &vault_core::VaultGuide, include_content: bool) -> Value {
    let mut map = Map::new();
    map.insert("name".into(), Value::String(guide.name.clone()));

    if include_content {
        map.insert("content".into(), Value::String(guide.content.clone()));
    }

    map.insert("category".into(), Value::String(guide.category.clone()));
    map.insert("status".into(), Value::String(guide.status.clone()));
    insert_opt_str(&mut map, "verified_at", &guide.verified_at);
    insert_opt_str(&mut map, "created_at", &guide.created_at);
    insert_opt_str(&mut map, "updated_at", &guide.updated_at);

    map.insert("version".into(), Value::Number(guide.version.into()));

    if !guide.tags.is_empty() {
        let arr: Vec<Value> = guide
            .tags
            .iter()
            .map(|s| Value::String(s.clone()))
            .collect();
        map.insert("tags".into(), Value::Array(arr));
    }

    if !guide.related_paths.is_empty() {
        let arr: Vec<Value> = guide
            .related_paths
            .iter()
            .map(|s| Value::String(s.clone()))
            .collect();
        map.insert("related_paths".into(), Value::Array(arr));
    }

    Value::Object(map)
}

fn insert_opt_str(map: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(s) = value {
        if !s.is_empty() {
            map.insert(key.into(), Value::String(s.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_defaults_removes_nulls() {
        let mut v = serde_json::json!({
            "path": "test",
            "value": null,
            "tags": [],
            "meta": {}
        });
        strip_defaults(&mut v);
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("path"));
        assert!(!obj.contains_key("value"));
        assert!(!obj.contains_key("tags"));
        assert!(!obj.contains_key("meta"));
    }

    #[test]
    fn test_strip_defaults_removes_default_values() {
        let mut v = serde_json::json!({
            "path": "test",
            "storage_mode": "vault",
            "category": "env_var"
        });
        strip_defaults(&mut v);
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("path"));
        assert!(!obj.contains_key("storage_mode"));
        assert!(!obj.contains_key("category"));
    }

    #[test]
    fn test_strip_defaults_keeps_non_defaults() {
        let mut v = serde_json::json!({
            "path": "test",
            "storage_mode": "keychain",
            "category": "api_key"
        });
        strip_defaults(&mut v);
        let obj = v.as_object().unwrap();
        assert_eq!(obj.get("storage_mode").unwrap(), "keychain");
        assert_eq!(obj.get("category").unwrap(), "api_key");
    }

    #[test]
    fn test_format_response_compact() {
        let v = serde_json::json!({"a": 1, "b": "hello"});
        let s = format_response(&v);
        // Compact JSON: no spaces after colons or commas
        assert!(!s.contains(": "));
        assert!(!s.contains(", "));
    }
}
