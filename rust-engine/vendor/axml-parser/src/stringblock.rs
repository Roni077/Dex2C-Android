//! String pool (ResStringPool) parser for AXML/ARSC.

use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::{Read, Seek};

use crate::constants::UTF8_FLAG;
use crate::error::ResParserError;

/// String pool chunk - contains UTF-8 or UTF-16 strings.
#[allow(dead_code)]
pub struct StringBlock {
    string_count: u32,
    style_count: u32,
    flags: u32,
    is_utf8: bool,
    strings_offset: u32,
    styles_offset: u32,
    string_offsets: Vec<u32>,
    style_offsets: Vec<u32>,
    charbuff: Vec<u8>,
    styles: Vec<u32>,
    cache: HashMap<usize, String>,
}

impl StringBlock {
    /// Parse string pool from buffer. `header_size` is the chunk size (total).
    pub fn parse<R: Read + Seek>(buff: &mut R, header_size: u32) -> Result<Self, ResParserError> {
        let string_count = buff
            .read_u32::<LittleEndian>()
            .map_err(|e| ResParserError(format!("Failed to read string count: {}", e)))?;
        let style_count = buff
            .read_u32::<LittleEndian>()
            .map_err(|e| ResParserError(format!("Failed to read style count: {}", e)))?;
        let flags = buff
            .read_u32::<LittleEndian>()
            .map_err(|e| ResParserError(format!("Failed to read flags: {}", e)))?;
        let is_utf8 = (flags & UTF8_FLAG) != 0;
        let strings_offset = buff
            .read_u32::<LittleEndian>()
            .map_err(|e| ResParserError(format!("Failed to read strings offset: {}", e)))?;

        let mut string_count = string_count;
        let header_part = style_count.saturating_mul(4).saturating_add(28);
        if strings_offset > header_part {
            let expected_offsets = (strings_offset - header_part) / 4;
            if expected_offsets != string_count {
                string_count = expected_offsets;
            }
        }

        let styles_offset = buff
            .read_u32::<LittleEndian>()
            .map_err(|e| ResParserError(format!("Failed to read styles offset: {}", e)))?;

        let mut string_offsets = Vec::with_capacity(string_count as usize);
        for _ in 0..string_count {
            string_offsets.push(
                buff.read_u32::<LittleEndian>()
                    .map_err(|e| ResParserError(format!("Failed to read string offset: {}", e)))?,
            );
        }

        let mut style_offsets = Vec::with_capacity(style_count as usize);
        for _ in 0..style_count {
            style_offsets.push(
                buff.read_u32::<LittleEndian>()
                    .map_err(|e| ResParserError(format!("Failed to read style offset: {}", e)))?,
            );
        }

        let mut size = (header_size - strings_offset) as usize;
        if styles_offset != 0 && style_count != 0 {
            size = (styles_offset - strings_offset) as usize;
        }

        let mut charbuff = vec![0u8; size];
        buff.read_exact(&mut charbuff)
            .map_err(|e| ResParserError(format!("Failed to read string data: {}", e)))?;

        let mut styles = Vec::new();
        if styles_offset != 0 && style_count != 0 {
            let style_size = (header_size - styles_offset) as usize;
            let style_count_u = (style_size / 4) as usize;
            for _ in 0..style_count_u {
                styles.push(
                    buff.read_u32::<LittleEndian>()
                        .map_err(|e| ResParserError(format!("Failed to read style: {}", e)))?,
                );
            }
        }

        Ok(StringBlock {
            string_count,
            style_count,
            flags,
            is_utf8,
            strings_offset,
            styles_offset,
            string_offsets,
            style_offsets,
            charbuff,
            styles,
            cache: HashMap::new(),
        })
    }

    /// Get string at index.
    pub fn get_string(&mut self, idx: usize) -> String {
        if let Some(s) = self.cache.get(&idx) {
            return s.clone();
        }
        if idx >= self.string_offsets.len() {
            return String::new();
        }
        let offset = self.string_offsets[idx] as usize;
        let s = if self.is_utf8 {
            self.decode_utf8(offset).unwrap_or_default()
        } else {
            self.decode_utf16(offset).unwrap_or_default()
        };
        self.cache.insert(idx, s.clone());
        s
    }

    fn decode_length(
        &self,
        offset: usize,
        sizeof_char: usize,
    ) -> Result<(usize, usize), ResParserError> {
        let sizeof_2chars = sizeof_char << 1;
        if offset + sizeof_2chars > self.charbuff.len() {
            return Err(ResParserError("String length out of bounds".to_string()));
        }
        let highbit = 0x80 << (8 * (sizeof_char - 1));

        let (length, size) = if sizeof_char == 1 {
            let length1 = self.charbuff[offset] as u32;
            let length2 = self.charbuff[offset + 1] as u32;
            if (length1 & highbit) != 0 {
                let length = ((length1 & !highbit) << 8) | length2;
                (length as usize, 2)
            } else {
                (length1 as usize, 1)
            }
        } else {
            let length1 = u16::from_le_bytes([self.charbuff[offset], self.charbuff[offset + 1]]);
            let length2 =
                u16::from_le_bytes([self.charbuff[offset + 2], self.charbuff[offset + 3]]);
            if (length1 & (highbit as u16)) != 0 {
                let length = ((length1 & !(highbit as u16)) as u32) << 16 | length2 as u32;
                (length as usize, 4)
            } else {
                (length1 as usize, 2)
            }
        };

        if sizeof_char == 1 && length > 0x7FFF {
            return Err(ResParserError(format!(
                "length of UTF-8 string is too large! At offset={}",
                offset
            )));
        }
        if sizeof_char == 2 && length > 0x7FFFFFFF {
            return Err(ResParserError(format!(
                "length of UTF-16 string is too large! At offset={}",
                offset
            )));
        }
        Ok((length, size))
    }

    fn decode_utf8(&self, offset: usize) -> Result<String, ResParserError> {
        let (str_len, skip) = self.decode_length(offset, 1)?;
        let offset = offset + skip;
        let (encoded_bytes, skip2) = self.decode_length(offset, 1)?;
        let offset = offset + skip2;

        if offset + encoded_bytes > self.charbuff.len() {
            return Ok(String::new());
        }
        let data = &self.charbuff[offset..offset + encoded_bytes];
        let s = String::from_utf8_lossy(data);
        let s = s.chars().take(str_len).collect::<String>();
        Ok(s)
    }

    fn decode_utf16(&self, offset: usize) -> Result<String, ResParserError> {
        let (str_len, skip) = self.decode_length(offset, 2)?;
        let offset = offset + skip;
        let encoded_bytes = str_len * 2;

        if offset + encoded_bytes > self.charbuff.len() {
            return Ok(String::new());
        }
        if offset + encoded_bytes + 2 <= self.charbuff.len() {
            let term = &self.charbuff[offset + encoded_bytes..offset + encoded_bytes + 2];
            if term != b"\x00\x00" {
                return Err(ResParserError(format!(
                    "UTF-16 String is not null terminated! At offset={}",
                    offset
                )));
            }
        }

        let data = &self.charbuff[offset..offset + encoded_bytes];
        let mut utf16 = Vec::with_capacity(str_len);
        for i in 0..str_len {
            if i * 2 + 1 < data.len() {
                let c = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
                utf16.push(c);
            }
        }
        Ok(String::from_utf16_lossy(&utf16))
    }

    pub fn len(&self) -> usize {
        self.string_count as usize
    }

    pub fn is_empty(&self) -> bool {
        self.string_count == 0
    }
}
