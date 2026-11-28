//! ResChunk_header - common chunk header for AXML/ARSC.

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Read, Seek, SeekFrom};

use crate::error::ResParserError;

pub const HEADER_SIZE: usize = 2 + 2 + 4;

/// Resource chunk header (ResChunk_header).
#[derive(Debug, Clone)]
pub struct ARSCHeader {
    pub start: u64,
    pub chunk_type: u16,
    pub header_size: u16,
    pub size: u32,
}

impl ARSCHeader {
    pub const SIZE: usize = HEADER_SIZE;

    pub fn read<R: Read + Seek>(
        buff: &mut R,
        expected_type: Option<u16>,
        possible_types: Option<&[u16]>,
    ) -> Result<Self, ResParserError> {
        let mut start = buff
            .seek(SeekFrom::Current(0))
            .map_err(|e| ResParserError(format!("Seek failed: {}", e)))?;

        let (chunk_type, header_size, size) = if let Some(possible) = possible_types {
            let result = loop {
                start = buff
                    .seek(SeekFrom::Current(0))
                    .map_err(|e| ResParserError(format!("Seek failed: {}", e)))?;
                let mut buf = [0u8; HEADER_SIZE];
                if buff
                    .read(&mut buf)
                    .map_err(|e| ResParserError(e.to_string()))?
                    != HEADER_SIZE
                {
                    return Err(ResParserError(
                        "Can not read over the buffer size!".to_string(),
                    ));
                }
                let mut c = std::io::Cursor::new(&buf);
                let ct = c.read_u16::<LittleEndian>().unwrap();
                let hs = c.read_u16::<LittleEndian>().unwrap();
                let sz = c.read_u32::<LittleEndian>().unwrap();
                if start == 0
                    || (possible.contains(&ct)
                        && hs >= HEADER_SIZE as u16
                        && sz > HEADER_SIZE as u32)
                {
                    break (ct, hs, sz);
                }
                buff.seek(SeekFrom::Start(start + 1))
                    .map_err(|e| ResParserError(format!("Seek failed: {}", e)))?;
            };
            result
        } else {
            let mut buf = [0u8; HEADER_SIZE];
            buff.read_exact(&mut buf).map_err(|_e| {
                ResParserError(format!(
                    "Can not read over the buffer size! Offset={}",
                    start
                ))
            })?;
            let mut c = std::io::Cursor::new(&buf);
            let ct = c.read_u16::<LittleEndian>().unwrap();
            let hs = c.read_u16::<LittleEndian>().unwrap();
            let sz = c.read_u32::<LittleEndian>().unwrap();
            (ct, hs, sz)
        };

        if let Some(exp) = expected_type {
            if chunk_type != exp {
                return Err(ResParserError(format!(
                    "Header type is not equal the expected type: Got 0x{:04x}, wanted 0x{:04x}",
                    chunk_type, exp
                )));
            }
        }

        if header_size < HEADER_SIZE as u16 {
            return Err(ResParserError(format!(
                "declared header size is smaller than required size of {}! Offset={}",
                HEADER_SIZE, start
            )));
        }
        if size < HEADER_SIZE as u32 {
            return Err(ResParserError(format!(
                "declared chunk size is smaller than required size of {}! Offset={}",
                HEADER_SIZE, start
            )));
        }
        if size < header_size as u32 {
            return Err(ResParserError(format!(
                "declared chunk size ({}) is smaller than header size ({})! Offset={}",
                size, header_size, start
            )));
        }

        Ok(ARSCHeader {
            start,
            chunk_type,
            header_size,
            size,
        })
    }

    pub fn end(&self) -> u64 {
        self.start + self.size as u64
    }

    pub fn type_(&self) -> u16 {
        self.chunk_type
    }
}
