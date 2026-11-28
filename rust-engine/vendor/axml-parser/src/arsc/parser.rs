//! ARSC (Android resources) parser.

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::arsc::config::{parse_res_table_config, ARSCResTableConfig};
use crate::constants::{
    FLAG_COMPACT, FLAG_COMPLEX, FLAG_OFFSET16, NO_ENTRY_16, NO_ENTRY_32, RES_STRING_POOL_TYPE,
    RES_TABLE_OVERLAYABLE_POLICY_TYPE, RES_TABLE_OVERLAYABLE_TYPE, RES_TABLE_PACKAGE_TYPE,
    RES_TABLE_TYPE, RES_TABLE_TYPE_SPEC_TYPE, RES_TABLE_TYPE_TYPE, TYPE_REFERENCE,
};
use crate::error::ResParserError;
use crate::formatters::format_value;
use crate::header::ARSCHeader;
use crate::stringblock::StringBlock;
use std::collections::{HashMap, HashSet};

/// One item inside a complex (bag) resource entry.
#[derive(Debug, Clone)]
pub struct ArscBagItem {
    pub name_id: u32,
    pub data_type: u8,
    pub data: u32,
    pub formatted: Option<String>,
}

/// Complex resource bag (style / attr / array / plurals).
#[derive(Debug, Clone)]
pub struct ArscBag {
    pub parent: u32,
    pub items: Vec<ArscBagItem>,
}

/// One named resource entry (`0x7f0b0001` → layout / activity_main).
#[derive(Debug, Clone)]
pub struct ArscResourceEntry {
    pub id: u32,
    pub package: String,
    pub type_name: String,
    pub name: String,
    /// Resolved / formatted scalar when available; themes/bag entries may be `None`.
    pub value: Option<String>,
    /// Raw Res_value type byte when a simple value was read.
    pub data_type: Option<u8>,
    /// Complex bag payload (styles, attrs, arrays, plurals).
    pub bag: Option<ArscBag>,
    /// Configuration this entry was defined under.
    pub config: ARSCResTableConfig,
}

/// Overlayable resource group (`RES_TABLE_OVERLAYABLE_TYPE`).
#[derive(Debug, Clone)]
pub struct OverlayableGroup {
    pub name: String,
    pub actor: String,
    pub policies: Vec<OverlayablePolicy>,
}

#[derive(Debug, Clone)]
pub struct OverlayablePolicy {
    pub flags: u32,
    pub entries: Vec<u32>,
}

/// ARSC (resources.arsc) parser with id → name lookup.
pub struct ARSCParser {
    pub packages: HashMap<String, Vec<String>>,
    /// Resource id → entry (first / default-ish config wins for id lookup).
    pub resources: HashMap<u32, ArscResourceEntry>,
    /// All typed entries including alternate configurations.
    pub all_entries: Vec<ArscResourceEntry>,
    /// Global table string pool (used by TYPE_STRING resource values).
    pub strings: Vec<String>,
    /// Overlayable declarations (for `overlayable.xml`).
    pub overlayables: Vec<OverlayableGroup>,
}

const FLAG_SPARSE: u8 = 0x01;

impl ARSCParser {
    pub fn new(raw_buff: &[u8]) -> Result<Self, ResParserError> {
        if raw_buff.len() < 8 || raw_buff.len() > 0xFFFFFFFF {
            return Err(ResParserError(format!(
                "Invalid file size {} for a resources.arsc file!",
                raw_buff.len()
            )));
        }
        let mut cursor = Cursor::new(raw_buff.to_vec());
        let table_header = ARSCHeader::read(&mut cursor, Some(RES_TABLE_TYPE), None)?;
        if table_header.size as usize > raw_buff.len() {
            return Err(ResParserError(format!(
                "File seems truncated. Size: {}, declared: {}",
                raw_buff.len(),
                table_header.size
            )));
        }
        let _package_count = cursor
            .read_u32::<LittleEndian>()
            .map_err(|e| ResParserError(format!("Failed to read package count: {}", e)))?;
        let _ = cursor.seek(SeekFrom::Start(
            table_header.start + table_header.header_size as u64,
        ));

        let mut packages: HashMap<String, Vec<String>> = HashMap::new();
        let mut resources: HashMap<u32, ArscResourceEntry> = HashMap::new();
        let mut all_entries: Vec<ArscResourceEntry> = Vec::new();
        let mut strings: Vec<String> = Vec::new();
        let mut overlayables: Vec<OverlayableGroup> = Vec::new();
        let end_pos = table_header.start + table_header.size as u64;

        while cursor
            .stream_position()
            .map_err(|e| ResParserError(e.to_string()))?
            <= end_pos.saturating_sub(ARSCHeader::SIZE as u64)
        {
            let res_header = match ARSCHeader::read(&mut cursor, None, None) {
                Ok(h) => h,
                Err(_) => break,
            };
            if res_header.end() > end_pos {
                break;
            }
            if res_header.type_() == RES_STRING_POOL_TYPE {
                if let Ok(mut pool) = StringBlock::parse(&mut cursor, res_header.size) {
                    if strings.is_empty() {
                        strings = (0..pool.len()).map(|i| pool.get_string(i)).collect();
                    }
                }
                let _ = cursor.seek(SeekFrom::Start(res_header.end()));
                continue;
            }
            if res_header.type_() == RES_TABLE_PACKAGE_TYPE {
                parse_package_chunk(
                    &mut cursor,
                    &res_header,
                    &mut packages,
                    &mut resources,
                    &mut all_entries,
                    &strings,
                    &mut overlayables,
                )?;
                let _ = cursor.seek(SeekFrom::Start(res_header.end()));
                continue;
            }
            let _ = cursor.seek(SeekFrom::Start(res_header.end()));
        }

        resolve_reference_values(&mut resources, &mut all_entries);

        Ok(ARSCParser {
            packages,
            resources,
            all_entries,
            strings,
            overlayables,
        })
    }

    pub fn get_packages_names(&self) -> Vec<String> {
        self.packages.keys().cloned().collect()
    }

    pub fn get_package_types(&self, name: &str) -> Option<&Vec<String>> {
        self.packages.get(name)
    }

    pub fn resolve_id(&self, id: u32) -> Option<String> {
        let e = self.resources.get(&id)?;
        Some(format_resource_ref(e))
    }

    pub fn id_to_java_name(&self) -> HashMap<u32, String> {
        self.resources
            .iter()
            .map(|(id, e)| (*id, format_resource_ref(e)))
            .collect()
    }

    pub fn id_to_string_value(&self) -> HashMap<u32, String> {
        self.resources
            .iter()
            .filter_map(|(id, e)| e.value.as_ref().map(|v| (*id, v.clone())))
            .collect()
    }

    pub fn parse_id(name: &str) -> Result<(u32, Option<String>), ResParserError> {
        if !name.starts_with('@') {
            return Err(ResParserError(format!(
                "Not a valid resource ID, must start with @: '{}'",
                name
            )));
        }
        let name = &name[1..];
        let (package, res_id_str) = if let Some(colon) = name.find(':') {
            (Some(name[..colon].to_string()), &name[colon + 1..])
        } else {
            (None, name)
        };
        if res_id_str.len() != 8 {
            return Err(ResParserError(format!(
                "Numerical ID is not 8 characters long: '{}'",
                res_id_str
            )));
        }
        let res_id = u32::from_str_radix(res_id_str, 16)
            .map_err(|_| ResParserError(format!("ID is not a hex ID: '{}'", res_id_str)))?;
        Ok((res_id, package))
    }
}

fn format_resource_ref(e: &ArscResourceEntry) -> String {
    let is_android = e.package == "android" || (e.id >> 24) == 0x01;
    if is_android {
        format!("android.R.{}.{}", e.type_name, e.name)
    } else {
        format!("R.{}.{}", e.type_name, e.name)
    }
}

fn parse_package_chunk(
    cursor: &mut Cursor<Vec<u8>>,
    res_header: &ARSCHeader,
    packages: &mut HashMap<String, Vec<String>>,
    resources: &mut HashMap<u32, ArscResourceEntry>,
    all_entries: &mut Vec<ArscResourceEntry>,
    global_strings: &[String],
    overlayables: &mut Vec<OverlayableGroup>,
) -> Result<(), ResParserError> {
    let pkg_id = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ResParserError(format!("Failed to read package id: {}", e)))?;
    let mut name_bytes = [0u8; 256];
    cursor
        .read_exact(&mut name_bytes)
        .map_err(|e| ResParserError(format!("Failed to read package name: {}", e)))?;
    let package_name = decode_utf16_name(&name_bytes);
    let type_strings_off = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ResParserError(format!("Failed to read typeStrings: {}", e)))?;
    let _last_public_type = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ResParserError(format!("Failed to read lastPublicType: {}", e)))?;
    let key_strings_off = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ResParserError(format!("Failed to read keyStrings: {}", e)))?;
    let _last_public_key = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ResParserError(format!("Failed to read lastPublicKey: {}", e)))?;

    cursor
        .seek(SeekFrom::Start(res_header.start + type_strings_off as u64))
        .map_err(|e| ResParserError(format!("Seek typeStrings: {}", e)))?;
    let type_sp_header = ARSCHeader::read(cursor, Some(RES_STRING_POOL_TYPE), None)?;
    let mut type_pool = StringBlock::parse(cursor, type_sp_header.size)?;
    let type_names: Vec<String> = (0..type_pool.len())
        .map(|i| sanitize_java_ident(&type_pool.get_string(i)))
        .collect();

    cursor
        .seek(SeekFrom::Start(res_header.start + key_strings_off as u64))
        .map_err(|e| ResParserError(format!("Seek keyStrings: {}", e)))?;
    let key_sp_header = ARSCHeader::read(cursor, Some(RES_STRING_POOL_TYPE), None)?;
    let mut key_pool = StringBlock::parse(cursor, key_sp_header.size)?;
    let key_names: Vec<String> = (0..key_pool.len())
        .map(|i| sanitize_java_ident(&key_pool.get_string(i)))
        .collect();

    let mut seen_types = HashSet::new();
    let mut package_types = Vec::new();

    let mut pos = cursor
        .seek(SeekFrom::Start(
            res_header.start
                + res_header.header_size as u64
                + type_sp_header.size as u64
                + key_sp_header.size as u64,
        ))
        .map_err(|e| ResParserError(e.to_string()))?;

    if pos < res_header.start + res_header.header_size as u64 {
        pos = cursor
            .seek(SeekFrom::Start(
                res_header.start + res_header.header_size as u64,
            ))
            .map_err(|e| ResParserError(e.to_string()))?;
    }

    while pos <= res_header.end().saturating_sub(ARSCHeader::SIZE as u64) {
        let sub = match ARSCHeader::read(cursor, None, None) {
            Ok(h) => h,
            Err(_) => break,
        };
        if sub.end() > res_header.end() {
            break;
        }
        if sub.type_() == RES_TABLE_TYPE_SPEC_TYPE {
            // skip
        } else if sub.type_() == RES_TABLE_TYPE_TYPE {
            let _ = parse_type_chunk(
                cursor,
                &sub,
                pkg_id,
                &package_name,
                &type_names,
                &key_names,
                global_strings,
                resources,
                all_entries,
                &mut seen_types,
                &mut package_types,
            );
        } else if sub.type_() == RES_TABLE_OVERLAYABLE_TYPE {
            if let Ok(group) = parse_overlayable_chunk(cursor, &sub) {
                overlayables.push(group);
            }
        }
        pos = cursor
            .seek(SeekFrom::Start(sub.end()))
            .map_err(|e| ResParserError(e.to_string()))?;
    }

    package_types.sort();
    packages.insert(package_name, package_types);
    Ok(())
}

fn parse_overlayable_chunk(
    cursor: &mut Cursor<Vec<u8>>,
    header: &ARSCHeader,
) -> Result<OverlayableGroup, ResParserError> {
    let mut name_bytes = [0u8; 256];
    let mut actor_bytes = [0u8; 256];
    cursor
        .read_exact(&mut name_bytes)
        .map_err(|e| ResParserError(e.to_string()))?;
    cursor
        .read_exact(&mut actor_bytes)
        .map_err(|e| ResParserError(e.to_string()))?;
    let name = decode_utf16_name(&name_bytes);
    let actor = decode_utf16_name(&actor_bytes);

    let mut policies = Vec::new();
    let mut pos = cursor
        .stream_position()
        .map_err(|e| ResParserError(e.to_string()))?;
    while pos + ARSCHeader::SIZE as u64 <= header.end() {
        let pol = match ARSCHeader::read(cursor, None, None) {
            Ok(h) => h,
            Err(_) => break,
        };
        if pol.end() > header.end() {
            break;
        }
        if pol.type_() == RES_TABLE_OVERLAYABLE_POLICY_TYPE {
            let flags = cursor.read_u32::<LittleEndian>().unwrap_or(0);
            let count = cursor.read_u32::<LittleEndian>().unwrap_or(0) as usize;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                if let Ok(id) = cursor.read_u32::<LittleEndian>() {
                    entries.push(id);
                }
            }
            policies.push(OverlayablePolicy { flags, entries });
        }
        pos = cursor
            .seek(SeekFrom::Start(pol.end()))
            .map_err(|e| ResParserError(e.to_string()))?;
    }

    Ok(OverlayableGroup {
        name,
        actor,
        policies,
    })
}

fn parse_type_chunk(
    cursor: &mut Cursor<Vec<u8>>,
    header: &ARSCHeader,
    pkg_id: u32,
    package_name: &str,
    type_names: &[String],
    key_names: &[String],
    global_strings: &[String],
    resources: &mut HashMap<u32, ArscResourceEntry>,
    all_entries: &mut Vec<ArscResourceEntry>,
    seen_types: &mut HashSet<String>,
    package_types: &mut Vec<String>,
) -> Result<(), ResParserError> {
    let type_id = cursor
        .read_u8()
        .map_err(|e| ResParserError(format!("type id: {}", e)))?;
    let flags = cursor
        .read_u8()
        .map_err(|e| ResParserError(format!("type flags: {}", e)))?;
    let _reserved = cursor
        .read_u16::<LittleEndian>()
        .map_err(|e| ResParserError(format!("type reserved: {}", e)))?;
    let entry_count = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ResParserError(format!("entryCount: {}", e)))?;
    let entries_start = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ResParserError(format!("entriesStart: {}", e)))?;

    let type_name = if type_id > 0 {
        type_names
            .get((type_id as usize) - 1)
            .cloned()
            .unwrap_or_else(|| format!("type{}", type_id))
    } else {
        format!("type{}", type_id)
    };
    if seen_types.insert(type_name.clone()) {
        package_types.push(type_name.clone());
    }

    let config = parse_res_table_config(cursor)?;

    let base_offset = header.start + entries_start as u64;
    let sparse = (flags & FLAG_SPARSE) != 0;
    let offset16 = (flags & FLAG_OFFSET16) != 0;

    let mut entries: Vec<(u32, u32)> = Vec::new();

    if sparse {
        for _ in 0..entry_count {
            let idx = cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| ResParserError(e.to_string()))? as u32;
            let off16 = cursor
                .read_u16::<LittleEndian>()
                .map_err(|e| ResParserError(e.to_string()))?;
            let offset = (off16 as u32).saturating_mul(4);
            entries.push((idx, offset));
        }
    } else {
        for i in 0..entry_count {
            let offset = if offset16 {
                let off16 = cursor
                    .read_u16::<LittleEndian>()
                    .map_err(|e| ResParserError(e.to_string()))?;
                if off16 == NO_ENTRY_16 {
                    continue;
                }
                (off16 as u32).saturating_mul(4)
            } else {
                let off = cursor
                    .read_u32::<LittleEndian>()
                    .map_err(|e| ResParserError(e.to_string()))?;
                if off == NO_ENTRY_32 {
                    continue;
                }
                off
            };
            entries.push((i, offset));
        }
    }

    for (entry_index, entry_off) in entries {
        let res_id = (pkg_id << 24) | ((type_id as u32) << 16) | (entry_index & 0xFFFF);
        let entry_pos = base_offset + entry_off as u64;
        if entry_pos + 8 > header.end() {
            continue;
        }
        if cursor.seek(SeekFrom::Start(entry_pos)).is_err() {
            continue;
        }
        let size = match cursor.read_u16::<LittleEndian>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let entry_flags = match cursor.read_u16::<LittleEndian>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let index = match cursor.read_u32::<LittleEndian>() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let key_idx = if (entry_flags & FLAG_COMPACT) != 0 {
            size as usize
        } else {
            index as usize
        };
        let name = key_names
            .get(key_idx)
            .cloned()
            .unwrap_or_else(|| format!("res_0x{:08x}", res_id));
        if name.is_empty() {
            continue;
        }
        let (value, data_type, bag) = read_entry_value(
            cursor,
            entry_flags,
            size,
            index,
            entry_pos,
            header.end(),
            global_strings,
        );
        let entry = ArscResourceEntry {
            id: res_id,
            package: package_name.to_string(),
            type_name: type_name.clone(),
            name,
            value,
            data_type,
            bag,
            config: config.clone(),
        };
        let replace = match resources.get(&res_id) {
            None => true,
            Some(existing) => !existing.config.is_default() && entry.config.is_default(),
        };
        if replace {
            resources.insert(res_id, entry.clone());
        }
        all_entries.push(entry);
    }

    Ok(())
}

fn read_entry_value(
    cursor: &mut Cursor<Vec<u8>>,
    entry_flags: u16,
    size: u16,
    index: u32,
    entry_pos: u64,
    chunk_end: u64,
    global_strings: &[String],
) -> (Option<String>, Option<u8>, Option<ArscBag>) {
    if (entry_flags & FLAG_COMPLEX) != 0 {
        // Complex: parent(u32) + count(u32) + count * (name u32 + Res_value 8)
        let bag_pos = entry_pos + 8;
        if bag_pos + 8 > chunk_end {
            return (None, None, None);
        }
        if cursor.seek(SeekFrom::Start(bag_pos)).is_err() {
            return (None, None, None);
        }
        let parent = match cursor.read_u32::<LittleEndian>() {
            Ok(v) => v,
            Err(_) => return (None, None, None),
        };
        let count = match cursor.read_u32::<LittleEndian>() {
            Ok(v) => v as usize,
            Err(_) => return (None, None, None),
        };
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let name_id = match cursor.read_u32::<LittleEndian>() {
                Ok(v) => v,
                Err(_) => break,
            };
            let _vsize = match cursor.read_u16::<LittleEndian>() {
                Ok(v) => v,
                Err(_) => break,
            };
            let _res0 = match cursor.read_u8() {
                Ok(v) => v,
                Err(_) => break,
            };
            let data_type = match cursor.read_u8() {
                Ok(v) => v,
                Err(_) => break,
            };
            let data = match cursor.read_u32::<LittleEndian>() {
                Ok(v) => v,
                Err(_) => break,
            };
            let formatted = format_res_data(data_type, data, global_strings);
            items.push(ArscBagItem {
                name_id,
                data_type,
                data,
                formatted,
            });
        }
        return (None, None, Some(ArscBag { parent, items }));
    }
    let (data_type, data) = if (entry_flags & FLAG_COMPACT) != 0 {
        (((entry_flags >> 8) & 0xff) as u8, index)
    } else {
        let value_pos = entry_pos + size as u64;
        if value_pos + 8 > chunk_end {
            return (None, None, None);
        }
        if cursor.seek(SeekFrom::Start(value_pos)).is_err() {
            return (None, None, None);
        }
        let _vsize = match cursor.read_u16::<LittleEndian>() {
            Ok(v) => v,
            Err(_) => return (None, None, None),
        };
        let _res0 = match cursor.read_u8() {
            Ok(v) => v,
            Err(_) => return (None, None, None),
        };
        let data_type = match cursor.read_u8() {
            Ok(v) => v,
            Err(_) => return (None, None, None),
        };
        let data = match cursor.read_u32::<LittleEndian>() {
            Ok(v) => v,
            Err(_) => return (None, None, None),
        };
        (data_type, data)
    };

    let formatted = format_res_data(data_type, data, global_strings);
    (formatted, Some(data_type), None)
}

fn format_res_data(data_type: u8, data: u32, global_strings: &[String]) -> Option<String> {
    if data_type == TYPE_REFERENCE && data != 0 {
        return Some(format!("@{:08X}", data));
    }
    let s = format_value(data_type, data, |idx| {
        global_strings
            .get(idx as usize)
            .cloned()
            .unwrap_or_default()
    });
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn resolve_reference_values(
    resources: &mut HashMap<u32, ArscResourceEntry>,
    all_entries: &mut [ArscResourceEntry],
) {
    let snapshot: HashMap<u32, Option<String>> = resources
        .iter()
        .map(|(id, e)| (*id, e.value.clone()))
        .collect();

    let resolve_one = |raw: &str| -> Option<String> {
        if !raw.starts_with('@') || raw.len() != 9 {
            return None;
        }
        let Ok(target) = u32::from_str_radix(&raw[1..], 16) else {
            return None;
        };
        let v = snapshot.get(&target)?.as_ref()?;
        if v.starts_with('@') {
            return None;
        }
        Some(v.clone())
    };

    for e in resources.values_mut() {
        if let Some(raw) = e.value.clone() {
            if let Some(v) = resolve_one(&raw) {
                e.value = Some(v);
            }
        }
    }
    for e in all_entries.iter_mut() {
        if let Some(raw) = e.value.clone() {
            if let Some(v) = resolve_one(&raw) {
                e.value = Some(v);
            }
        }
    }
}

fn sanitize_java_ident(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(s.len());
    for (i, ch) in s.chars().enumerate() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
            out.push(ch);
        } else if ch == '.' || ch == '-' || ch == '/' {
            out.push('_');
        } else if i == 0 {
            out.push('_');
        } else {
            out.push('_');
        }
    }
    if out
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        out.insert(0, '_');
    }
    out
}

fn decode_utf16_name(bytes: &[u8]) -> String {
    let mut utf16 = Vec::with_capacity(128);
    for i in (0..bytes.len().min(256)).step_by(2) {
        if i + 1 < bytes.len() {
            let c = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            if c == 0 {
                break;
            }
            utf16.push(c);
        }
    }
    String::from_utf16_lossy(&utf16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("ARSC")
            .join(name)
    }

    #[test]
    fn resolves_entries_from_sample_arsc() {
        let path = sample("TestActivity_resources.arsc");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(&path).expect("read arsc");
        let parser = ARSCParser::new(&data).expect("parse arsc");
        assert!(!parser.resources.is_empty(), "expected resource entries");
        assert!(!parser.packages.is_empty());
        let any = parser.resources.values().next().unwrap();
        let java = format_resource_ref(any);
        assert!(java.starts_with("R.") || java.starts_with("android.R."));
        assert!(java.matches('.').count() >= 2);
    }

    #[test]
    fn resolves_string_values_from_jamendo() {
        let path = sample("com.teleca.jamendo_35_resources.arsc");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(&path).unwrap();
        let parser = ARSCParser::new(&data).unwrap();
        let vals = parser.id_to_string_value();
        assert!(!vals.is_empty(), "expected some string values");
        let any = vals.values().next().unwrap();
        assert!(!any.is_empty());
    }

    #[test]
    fn parses_compact_resources() {
        let path = sample("compact-resources.arsc");
        if !path.exists() {
            return;
        }
        let data = std::fs::read(&path).unwrap();
        let parser = ARSCParser::new(&data).unwrap();
        assert!(!parser.all_entries.is_empty());
    }
}
