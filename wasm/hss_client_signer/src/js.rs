use js_sys::{Array, Object, Reflect};
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

pub fn get_optional_string(value: &JsValue, field_name: &str) -> Result<Option<String>, JsValue> {
    let field = Reflect::get(value, &JsValue::from_str(field_name))
        .map_err(|_| JsValue::from_str(&format!("Invalid args: invalid {field_name}")))?;
    if field.is_undefined() || field.is_null() {
        return Ok(None);
    }
    Ok(field
        .as_string()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty()))
}

pub fn get_required_u32(value: &JsValue, field_name: &str) -> Result<u32, JsValue> {
    let field = Reflect::get(value, &JsValue::from_str(field_name))
        .map_err(|_| JsValue::from_str(&format!("Invalid args: missing {field_name}")))?;
    let number = field
        .as_f64()
        .ok_or_else(|| JsValue::from_str(&format!("Invalid args: missing {field_name}")))?;
    if !number.is_finite() || number < 0.0 || number.fract() != 0.0 || number > u32::MAX as f64 {
        return Err(JsValue::from_str(&format!(
            "Invalid args: {field_name} must be a non-negative integer"
        )));
    }
    Ok(number as u32)
}

pub fn get_required_u16_vec(value: &JsValue, field_name: &str) -> Result<Vec<u16>, JsValue> {
    let field = Reflect::get(value, &JsValue::from_str(field_name))
        .map_err(|_| JsValue::from_str(&format!("Invalid args: missing {field_name}")))?;
    if !Array::is_array(&field) {
        return Err(JsValue::from_str(&format!(
            "Invalid args: {field_name} must be an array"
        )));
    }
    let array = Array::from(&field);
    let mut out = Vec::with_capacity(array.length() as usize);
    for item in array.iter() {
        let number = item.as_f64().ok_or_else(|| {
            JsValue::from_str(&format!("Invalid args: {field_name} must be an array"))
        })?;
        if !number.is_finite() || number < 0.0 || number.fract() != 0.0 || number > u16::MAX as f64
        {
            return Err(JsValue::from_str(&format!(
                "Invalid args: {field_name} contains an invalid participant id"
            )));
        }
        out.push(number as u16);
    }
    Ok(out)
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

pub fn set_f64(target: &Object, field_name: &str, value: f64) -> Result<(), JsValue> {
    Reflect::set(
        target,
        &JsValue::from_str(field_name),
        &JsValue::from_f64(value),
    )
    .map_err(|_| JsValue::from_str(&format!("Failed to serialize field {field_name}")))?;
    Ok(())
}

pub fn set_u16_vec(target: &Object, field_name: &str, value: &[u16]) -> Result<(), JsValue> {
    let array = Array::new_with_length(value.len() as u32);
    for (idx, item) in value.iter().enumerate() {
        array.set(idx as u32, JsValue::from_f64(*item as f64));
    }
    Reflect::set(target, &JsValue::from_str(field_name), &array)
        .map_err(|_| JsValue::from_str(&format!("Failed to serialize field {field_name}")))?;
    Ok(())
}
