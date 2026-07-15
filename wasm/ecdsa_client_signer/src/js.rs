use js_sys::{Object, Reflect};
use wasm_bindgen::prelude::*;

pub fn get_required_string(value: &JsValue, field_name: &str) -> Result<String, JsValue> {
    let field = Reflect::get(value, &JsValue::from_str(field_name))
        .map_err(|_| JsValue::from_str(&format!("Invalid args: missing {field_name}")))?;
    field
        .as_string()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| JsValue::from_str(&format!("Invalid args: missing {field_name}")))
}

pub fn object() -> Object {
    Object::new()
}

pub fn set_string(target: &Object, field_name: &str, value: &str) -> Result<(), JsValue> {
    Reflect::set(
        target,
        &JsValue::from_str(field_name),
        &JsValue::from_str(value),
    )
    .map_err(|_| JsValue::from_str(&format!("Failed to serialize field {field_name}")))?;
    Ok(())
}

pub fn set_u32(target: &Object, field_name: &str, value: u32) -> Result<(), JsValue> {
    Reflect::set(
        target,
        &JsValue::from_str(field_name),
        &JsValue::from_f64(value as f64),
    )
    .map_err(|_| JsValue::from_str(&format!("Failed to serialize field {field_name}")))?;
    Ok(())
}
