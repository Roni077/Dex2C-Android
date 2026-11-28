//! AXML parser - reads binary AXML and yields events (START_TAG, END_TAG, TEXT, END_DOCUMENT).

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Seek, SeekFrom};

use crate::constants::*;
use crate::error::ResParserError;
use crate::header::ARSCHeader;
use crate::public;
use crate::stringblock::StringBlock;

/// Event types from the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    StartDocument = 0,
    EndDocument = 1,
    StartTag = 2,
    EndTag = 3,
    Text = 4,
}

impl From<i32> for EventType {
    fn from(i: i32) -> Self {
        match i {
            0 => EventType::StartDocument,
            1 => EventType::EndDocument,
            2 => EventType::StartTag,
            3 => EventType::EndTag,
            4 => EventType::Text,
            _ => EventType::EndDocument,
        }
    }
}

/// AXML parser state machine.
pub struct AXMLParser {
    buff: Cursor<Vec<u8>>,
    buff_size: usize,
    valid: bool,
    pub axml_tampered: bool,
    pub packerwarning: bool,
    filesize: u32,
    sb: Option<StringBlock>,
    resource_ids: Vec<u32>,
    namespaces: Vec<(u32, u32)>,

    // Current event state
    pub m_event: i32,
    pub m_line_number: u32,
    m_name: i32,
    m_namespace_uri: i32,
    m_attributes: Vec<u32>,
    m_id_attribute: i32,
    m_class_attribute: i32,
    m_style_attribute: i32,
    m_attribute_count: usize,
    m_comment_index: u32,
}

impl AXMLParser {
    pub fn new(raw_buff: &[u8]) -> Self {
        let buff_size = raw_buff.len();
        let mut parser = AXMLParser {
            buff: Cursor::new(raw_buff.to_vec()),
            buff_size,
            valid: true,
            axml_tampered: false,
            packerwarning: false,
            filesize: 0,
            sb: None,
            resource_ids: Vec::new(),
            namespaces: Vec::new(),
            m_event: -1,
            m_line_number: 0,
            m_name: -1,
            m_namespace_uri: -1,
            m_attributes: Vec::new(),
            m_id_attribute: -1,
            m_class_attribute: -1,
            m_style_attribute: -1,
            m_attribute_count: 0,
            m_comment_index: 0xFFFFFFFF,
        };

        if let Err(_) = parser.init() {
            parser.valid = false;
        }
        parser
    }

    fn init(&mut self) -> Result<(), ResParserError> {
        if self.buff_size < 8 {
            return Err(ResParserError(format!(
                "Filesize is too small to be a valid AXML file! Filesize: {}",
                self.buff_size
            )));
        }
        if self.buff_size > 0xFFFFFFFF {
            return Err(ResParserError(format!(
                "Filesize is too large to be a valid AXML file! Filesize: {}",
                self.buff_size
            )));
        }

        let axml_header = ARSCHeader::read(&mut self.buff, Some(RES_XML_TYPE), None)?;
        self.filesize = axml_header.size;

        if axml_header.header_size != 8 {
            return Err(ResParserError(format!(
                "This does not look like an AXML file. header size does not equal 8! header size = {}",
                axml_header.header_size
            )));
        }
        if self.filesize > self.buff_size as u32 {
            return Err(ResParserError(format!(
                "This does not look like an AXML file. Declared filesize does not match real size: {} vs {}",
                self.filesize, self.buff_size
            )));
        }
        if self.filesize < self.buff_size as u32 {
            self.axml_tampered = true;
        }
        if axml_header.type_() != RES_XML_TYPE {
            self.axml_tampered = true;
        }

        let header = ARSCHeader::read(&mut self.buff, Some(RES_STRING_POOL_TYPE), None)?;
        if header.header_size != 0x1C {
            return Err(ResParserError(format!(
                "String chunk header size does not equal 28! header size = {}",
                header.header_size
            )));
        }

        let sb = StringBlock::parse(&mut self.buff, header.size)?;
        self.sb = Some(sb);

        self.buff
            .seek(SeekFrom::Start(
                axml_header.start + axml_header.header_size as u64 + header.size as u64,
            ))
            .map_err(|e| ResParserError(e.to_string()))?;

        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    fn reset_event(&mut self) {
        self.m_event = -1;
        self.m_line_number = 0;
        self.m_name = -1;
        self.m_namespace_uri = -1;
        self.m_attributes.clear();
        self.m_id_attribute = -1;
        self.m_class_attribute = -1;
        self.m_style_attribute = -1;
    }

    /// Advance to next event. Returns the event type.
    pub fn next(&mut self) -> i32 {
        self.do_next();
        self.m_event
    }

    fn do_next(&mut self) {
        if self.m_event == END_DOCUMENT {
            return;
        }

        self.reset_event();

        while self.valid {
            let pos = self.buff.stream_position().unwrap_or(0) as u32;
            if pos >= self.filesize {
                self.m_event = END_DOCUMENT;
                break;
            }

            let possible_types: [u16; 6] = [256, 257, 258, 259, 260, 384];
            let h = match ARSCHeader::read(&mut self.buff, None, Some(&possible_types)) {
                Ok(h) => h,
                Err(_) => {
                    self.valid = false;
                    return;
                }
            };

            if h.type_() == RES_XML_RESOURCE_MAP_TYPE {
                if h.size < 8 || (h.size % 4) != 0 {
                    self.valid = false;
                    return;
                }
                for _ in 0..((h.size - h.header_size as u32) / 4) {
                    if let Ok(id) = self.buff.read_u32::<LittleEndian>() {
                        self.resource_ids.push(id);
                    }
                }
                continue;
            }

            if h.type_() < RES_XML_FIRST_CHUNK_TYPE || h.type_() > RES_XML_LAST_CHUNK_TYPE {
                let _ = self.buff.seek(SeekFrom::Start(h.end()));
                continue;
            }

            if h.header_size != 0x10 {
                let _ = self.buff.seek(SeekFrom::Start(h.end()));
                continue;
            }

            self.m_line_number = self.buff.read_u32::<LittleEndian>().unwrap_or(0);
            self.m_comment_index = self.buff.read_u32::<LittleEndian>().unwrap_or(0xFFFFFFFF);

            if h.type_() == RES_XML_START_NAMESPACE_TYPE {
                let prefix = self.buff.read_u32::<LittleEndian>().unwrap_or(0);
                let uri = self.buff.read_u32::<LittleEndian>().unwrap_or(0);
                self.namespaces.push((prefix, uri));
                continue;
            }

            if h.type_() == RES_XML_END_NAMESPACE_TYPE {
                let prefix = self.buff.read_u32::<LittleEndian>().unwrap_or(0);
                let uri = self.buff.read_u32::<LittleEndian>().unwrap_or(0);
                if let Some(idx) = self
                    .namespaces
                    .iter()
                    .position(|&(p, u)| p == prefix && u == uri)
                {
                    self.namespaces.remove(idx);
                }
                continue;
            }

            if h.type_() == RES_XML_START_ELEMENT_TYPE {
                self.m_namespace_uri = self.buff.read_u32::<LittleEndian>().unwrap_or(0) as i32;
                self.m_name = self.buff.read_u32::<LittleEndian>().unwrap_or(0) as i32;
                let _at_start = self.buff.read_u16::<LittleEndian>().unwrap_or(0);
                let at_size = self.buff.read_u16::<LittleEndian>().unwrap_or(20);
                let attribute_count_raw = self.buff.read_u32::<LittleEndian>().unwrap_or(0);
                let class_attr = self.buff.read_u32::<LittleEndian>().unwrap_or(0);

                self.m_id_attribute = ((attribute_count_raw >> 16) as i32) - 1;
                self.m_attribute_count = (attribute_count_raw & 0xFFFF) as usize;
                self.m_style_attribute = ((class_attr >> 16) as i32) - 1;
                self.m_class_attribute = (class_attr & 0xFFFF) as i32 - 1;

                for _ in 0..self.m_attribute_count {
                    for _ in 0..ATTRIBUTE_LENGTH {
                        self.m_attributes
                            .push(self.buff.read_u32::<LittleEndian>().unwrap_or(0));
                    }
                    if at_size > 20 {
                        let skip = (at_size - 20) as u64;
                        let _ = self.buff.seek(SeekFrom::Current(skip as i64));
                    }
                }

                for i in
                    (ATTRIBUTE_IX_VALUE_TYPE..self.m_attributes.len()).step_by(ATTRIBUTE_LENGTH)
                {
                    if i < self.m_attributes.len() {
                        self.m_attributes[i] = self.m_attributes[i] >> 24;
                    }
                }
                self.m_event = START_TAG;
                break;
            }

            if h.type_() == RES_XML_END_ELEMENT_TYPE {
                self.m_namespace_uri = self.buff.read_u32::<LittleEndian>().unwrap_or(0) as i32;
                self.m_name = self.buff.read_u32::<LittleEndian>().unwrap_or(0) as i32;
                self.m_event = END_TAG;
                break;
            }

            if h.type_() == RES_XML_CDATA_TYPE {
                self.m_name = self.buff.read_u32::<LittleEndian>().unwrap_or(0) as i32;
                let _size = self.buff.read_u16::<LittleEndian>().unwrap_or(0);
                let _res0 = self.buff.read_u8().unwrap_or(0);
                let _data_type = self.buff.read_u8().unwrap_or(0);
                let _data = self.buff.read_u32::<LittleEndian>().unwrap_or(0);
                self.m_event = TEXT;
                break;
            }

            let _ = self.buff.seek(SeekFrom::Start(h.end()));
        }
    }

    pub fn name(&mut self) -> String {
        if self.m_name == -1 || (self.m_event != START_TAG && self.m_event != END_TAG) {
            return String::new();
        }
        self.sb
            .as_mut()
            .map(|sb| sb.get_string(self.m_name as usize))
            .unwrap_or_default()
    }

    pub fn namespace(&mut self) -> String {
        if self.m_name == -1 || (self.m_event != START_TAG && self.m_event != END_TAG) {
            return String::new();
        }
        if self.m_namespace_uri == -1 {
            return String::new();
        }
        self.sb
            .as_mut()
            .map(|sb| sb.get_string(self.m_namespace_uri as usize))
            .unwrap_or_default()
    }

    pub fn nsmap(&mut self) -> std::collections::HashMap<String, String> {
        let mut nsmap = std::collections::HashMap::new();
        if let Some(sb) = &mut self.sb {
            let seen: std::collections::HashSet<(u32, u32)> =
                self.namespaces.iter().cloned().collect();
            for (k, v) in seen {
                let s_prefix = sb.get_string(k as usize);
                let s_uri = sb.get_string(v as usize);
                if !s_uri.is_empty() && !s_prefix.is_empty() {
                    nsmap.insert(s_prefix, s_uri.trim().to_string());
                }
            }
        }
        nsmap
    }

    pub fn text(&mut self) -> String {
        if self.m_name == -1 || self.m_event != TEXT {
            return String::new();
        }
        self.sb
            .as_mut()
            .map(|sb| sb.get_string(self.m_name as usize))
            .unwrap_or_default()
    }

    pub fn comment(&mut self) -> Option<String> {
        if self.m_comment_index == 0xFFFFFFFF {
            return None;
        }
        self.sb
            .as_mut()
            .map(|sb| sb.get_string(self.m_comment_index as usize))
            .filter(|s| !s.is_empty())
    }

    pub fn get_attribute_count(&self) -> i32 {
        if self.m_event != START_TAG {
            return -1;
        }
        self.m_attribute_count as i32
    }

    fn get_attribute_offset(&self, index: usize) -> usize {
        index * ATTRIBUTE_LENGTH
    }

    pub fn get_attribute_uri(&self, index: usize) -> u32 {
        let offset = self.get_attribute_offset(index);
        self.m_attributes
            .get(offset + ATTRIBUTE_IX_NAMESPACE_URI)
            .copied()
            .unwrap_or(0xFFFFFFFF)
    }

    pub fn get_attribute_namespace(&mut self, index: usize) -> String {
        let uri = self.get_attribute_uri(index);
        if uri == 0xFFFFFFFF {
            return String::new();
        }
        self.sb
            .as_mut()
            .map(|sb| sb.get_string(uri as usize))
            .unwrap_or_default()
    }

    pub fn get_attribute_name(&mut self, index: usize) -> String {
        let offset = self.get_attribute_offset(index);
        let name_idx = self
            .m_attributes
            .get(offset + ATTRIBUTE_IX_NAME)
            .copied()
            .unwrap_or(0);
        let res = self
            .sb
            .as_mut()
            .map(|sb| sb.get_string(name_idx as usize))
            .unwrap_or_default();

        let attr = if (name_idx as usize) < self.resource_ids.len() {
            Some(self.resource_ids[name_idx as usize])
        } else {
            None
        };

        if let Some(attr_id) = attr {
            if let Some(name) = public::attribute_id_to_name(attr_id) {
                return name;
            }
            self.packerwarning = true;
        }

        if res.is_empty() || res == ":" {
            if let Some(attr_id) = attr {
                return format!("android:UNKNOWN_SYSTEM_ATTRIBUTE_{:08x}", attr_id);
            }
        }
        res
    }

    pub fn get_attribute_value_type(&self, index: usize) -> u8 {
        let offset = self.get_attribute_offset(index);
        self.m_attributes
            .get(offset + ATTRIBUTE_IX_VALUE_TYPE)
            .copied()
            .unwrap_or(0) as u8
    }

    pub fn get_attribute_value_data(&self, index: usize) -> u32 {
        let offset = self.get_attribute_offset(index);
        self.m_attributes
            .get(offset + ATTRIBUTE_IX_VALUE_DATA)
            .copied()
            .unwrap_or(0)
    }

    pub fn get_attribute_value(&mut self, index: usize) -> String {
        let offset = self.get_attribute_offset(index);
        let value_type = self
            .m_attributes
            .get(offset + ATTRIBUTE_IX_VALUE_TYPE)
            .copied()
            .unwrap_or(0) as u8;
        if value_type == TYPE_STRING {
            let value_string = self
                .m_attributes
                .get(offset + ATTRIBUTE_IX_VALUE_STRING)
                .copied()
                .unwrap_or(0);
            return self
                .sb
                .as_mut()
                .map(|sb| sb.get_string(value_string as usize))
                .unwrap_or_default();
        }
        String::new()
    }

    pub fn namespaces_open(&self) -> usize {
        self.namespaces.len()
    }

    /// Get string at pool index (for format_value lookup).
    pub fn get_string_at(&mut self, idx: u32) -> String {
        self.sb
            .as_mut()
            .map(|sb| sb.get_string(idx as usize))
            .unwrap_or_default()
    }
}
