// Plain hex codecs for the q=7933 JSON <-> C++ boundary.

pub fn bytes_to_hex(v: &[u8]) -> String {
    let mut out = String::with_capacity(v.len() * 2);
    for b in v {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).ok_or("invalid hex digit")?;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or("invalid hex digit")?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

#[allow(dead_code)]
pub fn u16_vec_to_hex(v: &[u16]) -> String {
    let mut out = String::with_capacity(v.len() * 4);
    for x in v {
        out.push_str(&format!("{:04x}", x));
    }
    out
}

pub fn hex_to_u16_vec(s: &str) -> Result<Vec<u16>, String> {
    if s.len() % 4 != 0 {
        return Err("u16-hex string length must be a multiple of 4".to_string());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 4);
    let mut i = 0;
    while i < bytes.len() {
        let chunk = std::str::from_utf8(&bytes[i..i + 4])
            .map_err(|_| "invalid utf8 in hex".to_string())?;
        let v = u16::from_str_radix(chunk, 16).map_err(|_| "invalid hex digit".to_string())?;
        out.push(v);
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip() {
        let v: Vec<u8> = (0..=255).collect();
        assert_eq!(hex_to_bytes(&bytes_to_hex(&v)).unwrap(), v);
    }

    #[test]
    fn u16_round_trip() {
        let v: Vec<u16> = vec![0, 1, 7933, 65535, 4242];
        assert_eq!(hex_to_u16_vec(&u16_vec_to_hex(&v)).unwrap(), v);
    }

    #[test]
    fn rejects_malformed_hex() {
        assert!(hex_to_bytes("abc").is_err());
        assert!(hex_to_bytes("zz").is_err());
        assert!(hex_to_u16_vec("abc").is_err());
    }
}
