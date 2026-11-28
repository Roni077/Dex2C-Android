//! string_ids and string_data_item (MUTF-8).

use crate::bounds::{table_end, vec_with_capacity};
use crate::error::{DexError, Result};
use crate::leb128::{read_u32, read_uleb128};

/// string_id_item: offset to string_data. We only store offsets; string data is in data section.
#[derive(Clone, Debug)]
pub struct DexStrings {
    /// For each string_id index, offset into file to string_data_item.
    offsets: Vec<u32>,
}

impl DexStrings {
    pub fn parse(data: &[u8], header: &super::DexHeader) -> Result<Self> {
        let n = header.string_ids_size as usize;
        let off = header.string_ids_off as usize;
        if n == 0 {
            return Ok(Self { offsets: vec![] });
        }
        let size_needed = table_end(off, n, 4, "string_ids")?;
        if data.len() < size_needed {
            return Err(DexError::Truncated("string_ids".into()));
        }
        let mut offsets = vec_with_capacity(n, "string_ids")?;
        for i in 0..n {
            let o = read_u32(data, off + i * 4).ok_or(DexError::Truncated("string_id_item".into()))?;
            offsets.push(o);
        }
        Ok(Self { offsets })
    }

    /// Get raw MUTF-8 slice for `idx` (excluding trailing NUL).
    pub fn get_raw_bytes<'a>(&self, data: &'a [u8], idx: u32) -> Result<&'a [u8]> {
        let idx = idx as usize;
        let offset = *self.offsets.get(idx).ok_or(DexError::Truncated("string index".into()))? as usize;
        if offset >= data.len() {
            return Err(DexError::Truncated("string_data_off".into()));
        }
        let (_utf16_size, n) = read_uleb128(data, offset).ok_or(DexError::Truncated("utf16_size".into()))?;
        let start = offset + n;
        let mut end = start;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }
        Ok(&data[start..end])
    }

    /// Borrow string zero-copy when pure ASCII (`< 0x80`), or decode MUTF-8 (with surrogate pairs) when needed.
    pub fn get_cow<'a>(&self, data: &'a [u8], idx: u32) -> Result<std::borrow::Cow<'a, str>> {
        let bytes = self.get_raw_bytes(data, idx)?;
        if bytes.iter().all(|&b| b < 0x80) {
            let s = std::str::from_utf8(bytes)
                .map_err(|_| DexError::Parse("invalid MUTF-8".into()))?;
            Ok(std::borrow::Cow::Borrowed(s))
        } else {
            decode_mutf8(bytes)
                .map(std::borrow::Cow::Owned)
                .map_err(DexError::Parse)
        }
    }

    /// Get string at index. Reads string_data_item: uleb128 utf16_size, then MUTF-8 data until 0.
    pub fn get(&self, data: &[u8], idx: u32) -> Result<String> {
        let bytes = self.get_raw_bytes(data, idx)?;
        decode_mutf8(bytes).map_err(DexError::Parse)
    }
}

/// Encode a Rust `&str` to MUTF-8 bytes (no trailing NUL).
pub fn encode_mutf8(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for ch in s.chars() {
        let cp = ch as u32;
        if cp != 0 && cp <= 0x7f {
            out.push(cp as u8);
        } else if cp <= 0x7ff {
            out.push((0xc0 | ((cp >> 6) & 0x1f)) as u8);
            out.push((0x80 | (cp & 0x3f)) as u8);
        } else if cp <= 0xffff {
            out.push((0xe0 | ((cp >> 12) & 0x0f)) as u8);
            out.push((0x80 | ((cp >> 6) & 0x3f)) as u8);
            out.push((0x80 | (cp & 0x3f)) as u8);
        } else {
            // Supplementary plane → UTF-16 surrogate pair in MUTF-8
            let cp2 = cp - 0x10000;
            let high = 0xd800 + ((cp2 >> 10) & 0x3ff);
            let low = 0xdc00 + (cp2 & 0x3ff);
            for half in [high, low] {
                out.push((0xe0 | ((half >> 12) & 0x0f)) as u8);
                out.push((0x80 | ((half >> 6) & 0x3f)) as u8);
                out.push((0x80 | (half & 0x3f)) as u8);
            }
        }
    }
    out
}

/// Decode MUTF-8 to String. Handles 1/2/3-byte sequences, `0xC0 0x80` NUL, and UTF-16 surrogate pairs.
pub fn decode_mutf8(bytes: &[u8]) -> std::result::Result<String, String> {
    if bytes.iter().all(|&b| b < 0x80) {
        return std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| "invalid MUTF-8".to_string());
    }

    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b & 0x80 == 0 {
            units.push(b as u16);
            i += 1;
        } else if b & 0xe0 == 0xc0 {
            if i + 1 >= bytes.len() {
                return Err("truncated MUTF-8".into());
            }
            let b1 = bytes[i + 1];
            if (b1 & 0xc0) != 0x80 {
                return Err("invalid MUTF-8".into());
            }
            let c = (((b & 0x1f) as u16) << 6) | ((b1 & 0x3f) as u16);
            units.push(c);
            i += 2;
        } else if b & 0xf0 == 0xe0 {
            if i + 2 >= bytes.len() {
                return Err("truncated MUTF-8".into());
            }
            let b1 = bytes[i + 1];
            let b2 = bytes[i + 2];
            if (b1 & 0xc0) != 0x80 || (b2 & 0xc0) != 0x80 {
                return Err("invalid MUTF-8".into());
            }
            let c = (((b & 0x0f) as u16) << 12)
                | (((b1 & 0x3f) as u16) << 6)
                | ((b2 & 0x3f) as u16);
            units.push(c);
            i += 3;
        } else {
            return Err("invalid MUTF-8".into());
        }
    }

    Ok(char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_mutf8_ascii_and_nul() {
        assert_eq!(decode_mutf8(b"Hello/World").unwrap(), "Hello/World");
        assert_eq!(decode_mutf8(&[0xC0, 0x80]).unwrap(), "\0");
        assert_eq!(
            decode_mutf8(&[b'a', 0xC0, 0x80, b'b']).unwrap(),
            "a\0b"
        );
        assert_eq!(encode_mutf8("a\0b"), vec![b'a', 0xC0, 0x80, b'b']);
    }

    #[test]
    fn decode_mutf8_bmp_multibyte() {
        let s = "café 你好 Ω";
        let enc = encode_mutf8(s);
        assert_eq!(decode_mutf8(&enc).unwrap(), s);
    }

    #[test]
    fn decode_mutf8_supplementary_surrogate_pairs() {
        // U+1F600 😀 -> UTF-16: D83D DE00 -> MUTF-8: ED A0 BD ED B8 80
        let raw_emoji = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        assert_eq!(decode_mutf8(&raw_emoji).unwrap(), "😀");

        // U+10437 𐐷 -> UTF-16: D801 DC37
        let mixed = "prefix 😀𐐷🚀 suffix";
        let enc = encode_mutf8(mixed);
        assert_eq!(decode_mutf8(&enc).unwrap(), mixed);
    }

    #[test]
    fn decode_mutf8_unpaired_surrogates_replace_with_fffd() {
        // Lone high surrogate D83D
        let lone_high = [0xED, 0xA0, 0xBD];
        assert_eq!(decode_mutf8(&lone_high).unwrap(), "\u{fffd}");

        // Lone low surrogate DE00 followed by 'x'
        let lone_low = [0xED, 0xB8, 0x80, b'x'];
        assert_eq!(decode_mutf8(&lone_low).unwrap(), "\u{fffd}x");
    }

    #[test]
    fn decode_mutf8_invalid_and_truncated_errors() {
        assert!(decode_mutf8(&[0xC2]).is_err());
        assert!(decode_mutf8(&[0xED, 0xA0]).is_err());
        assert!(decode_mutf8(&[0xC2, 0x00]).is_err());
        assert!(decode_mutf8(&[0xE0, 0x80, 0x00]).is_err());
        assert!(decode_mutf8(&[0xF0, 0x9F, 0x98, 0x80]).is_err());
        assert!(decode_mutf8(&[0x80]).is_err());
    }
}
