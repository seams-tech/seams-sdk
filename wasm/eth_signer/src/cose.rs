use ciborium::Value as CborValue;
use p256::PublicKey;
use wasm_bindgen::prelude::*;

fn cbor_int(value: &CborValue) -> Result<i128, String> {
    match value {
        CborValue::Integer(i) => Ok((*i).into()),
        _ => Err("COSE key field must be an integer".to_string()),
    }
}

fn required_int(map: &[(CborValue, CborValue)], label: i128, field: &str) -> Result<i128, String> {
    for (key, value) in map {
        if cbor_int(key)? == label {
            return cbor_int(value);
        }
    }
    Err(format!("COSE key missing {field}"))
}

fn required_bytes(
    map: &[(CborValue, CborValue)],
    label: i128,
    field: &str,
) -> Result<Vec<u8>, String> {
    for (key, value) in map {
        if cbor_int(key)? == label {
            return match value {
                CborValue::Bytes(bytes) => Ok(bytes.clone()),
                _ => Err(format!("COSE key {field} must be bytes")),
            };
        }
    }
    Err(format!("COSE key missing {field}"))
}

pub fn decode_cose_p256_public_key_raw(cose_public_key: &[u8]) -> Result<[u8; 64], String> {
    let cbor_value: CborValue = ciborium::from_reader(cose_public_key)
        .map_err(|e| format!("Failed to parse COSE CBOR: {e}"))?;
    let map = match cbor_value {
        CborValue::Map(map) => map,
        _ => return Err("COSE key must be a map".to_string()),
    };

    if required_int(&map, 1, "kty")? != 2 {
        return Err("COSE key kty must be EC2".to_string());
    }
    if required_int(&map, 3, "alg")? != -7 {
        return Err("COSE key alg must be ES256".to_string());
    }
    if required_int(&map, -1, "crv")? != 1 {
        return Err("COSE key crv must be P-256".to_string());
    }

    let x = required_bytes(&map, -2, "x")?;
    let y = required_bytes(&map, -3, "y")?;
    if x.len() != 32 || y.len() != 32 {
        return Err("COSE key x/y must be 32 bytes".to_string());
    }

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    PublicKey::from_sec1_bytes(&sec1).map_err(|_| "COSE key point is not on P-256".to_string())?;

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&x);
    out[32..].copy_from_slice(&y);
    Ok(out)
}

pub fn decode_cose_p256_public_key(cose_public_key: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    decode_cose_p256_public_key_raw(&cose_public_key)
        .map(|out| out.to_vec())
        .map_err(|err| JsValue::from_str(&err))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cose_key(x: Vec<u8>, y: Vec<u8>, alg: i64, crv: i64) -> Vec<u8> {
        let map = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
            (CborValue::Integer(3.into()), CborValue::Integer(alg.into())),
            (CborValue::Integer((-1).into()), CborValue::Integer(crv.into())),
            (CborValue::Integer((-2).into()), CborValue::Bytes(x)),
            (CborValue::Integer((-3).into()), CborValue::Bytes(y)),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&map, &mut out).unwrap();
        out
    }

    #[test]
    fn decodes_valid_p256_cose_key() {
        let x = hex_literal::hex!("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296").to_vec();
        let y = hex_literal::hex!("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").to_vec();
        let decoded = decode_cose_p256_public_key_raw(&cose_key(x.clone(), y.clone(), -7, 1))
            .expect("valid key");
        assert_eq!(&decoded[..32], x.as_slice());
        assert_eq!(&decoded[32..], y.as_slice());
    }

    #[test]
    fn rejects_wrong_algorithm() {
        let x = vec![0u8; 32];
        let y = vec![0u8; 32];
        let err = decode_cose_p256_public_key_raw(&cose_key(x, y, -257, 1)).unwrap_err();
        assert!(err.contains("alg"));
    }

    #[test]
    fn rejects_wrong_coordinate_length() {
        let x = vec![1u8; 31];
        let y = vec![2u8; 32];
        let err = decode_cose_p256_public_key_raw(&cose_key(x, y, -7, 1)).unwrap_err();
        assert!(err.contains("32 bytes"));
    }

    #[test]
    fn rejects_missing_coordinate() {
        let map = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
            (CborValue::Integer(3.into()), CborValue::Integer((-7).into())),
            (CborValue::Integer((-1).into()), CborValue::Integer(1.into())),
            (CborValue::Integer((-2).into()), CborValue::Bytes(vec![1u8; 32])),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&map, &mut out).unwrap();
        let err = decode_cose_p256_public_key_raw(&out).unwrap_err();
        assert!(err.contains("missing y"));
    }

    #[test]
    fn rejects_invalid_p256_point() {
        let x = vec![0u8; 32];
        let y = vec![0u8; 32];
        let err = decode_cose_p256_public_key_raw(&cose_key(x, y, -7, 1)).unwrap_err();
        assert!(err.contains("P-256"));
    }
}
