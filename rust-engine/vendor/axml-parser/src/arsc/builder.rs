//! Pure-Rust `resources.arsc` (ResTable) builder.

use crate::constants::{
    FLAG_COMPLEX, FLAG_PUBLIC, NO_ENTRY_32, RES_STRING_POOL_TYPE, RES_TABLE_PACKAGE_TYPE,
    RES_TABLE_TYPE, RES_TABLE_TYPE_SPEC_TYPE, RES_TABLE_TYPE_TYPE, TYPE_INT_BOOLEAN, TYPE_INT_COLOR_ARGB8,
    TYPE_INT_DEC, TYPE_INT_HEX, TYPE_NULL, TYPE_REFERENCE, TYPE_STRING,
};
use crate::error::ResParserError;

const SPEC_PUBLIC: u32 = 0x4000_0000;
const PKG_HEADER_SIZE: u16 = 288;
const CONFIG_SIZE: u32 = 64;

/// High-level resource value for the ARSC builder.
#[derive(Debug, Clone)]
pub enum ArscBuildValue {
    Null,
    String(String),
    Reference(u32),
    IntDec(i32),
    IntHex(u32),
    Bool(bool),
    ColorArgb8(u32),
    /// Raw Res_value type/data (escape hatch).
    Raw { data_type: u8, data: u32 },
    /// Complex bag (style / array / plurals / attr).
    Bag {
        parent: u32,
        items: Vec<(u32, u8, u32)>, // (name_id, data_type, data)
    },
}

/// One resource entry under a type + config.
#[derive(Debug, Clone)]
pub struct ArscBuildEntry {
    /// Entry index within the type (low 16 bits of resource id).
    pub entry_index: u16,
    pub name: String,
    pub value: ArscBuildValue,
    pub public: bool,
}

/// One `ResTable_type` configuration chunk for a type.
#[derive(Debug, Clone, Default)]
pub struct ArscBuildConfig {
    /// Apktool-style qualifier without leading `-` (empty = default).
    pub qualifier: String,
    /// Raw ResTable_config bytes if known; otherwise a default empty config is written.
    pub raw: Option<Vec<u8>>,
    pub entries: Vec<ArscBuildEntry>,
}

/// One resource type (`string`, `layout`, …).
#[derive(Debug, Clone)]
pub struct ArscBuildType {
    pub name: String,
    /// 1-based type id; assigned automatically if 0.
    pub type_id: u8,
    pub configs: Vec<ArscBuildConfig>,
}

/// Input model for building a single-package `resources.arsc`.
#[derive(Debug, Clone)]
pub struct ArscBuildInput {
    pub package_id: u32,
    pub package_name: String,
    pub types: Vec<ArscBuildType>,
}

/// Build a complete `resources.arsc` blob.
pub fn build_arsc(input: &ArscBuildInput) -> Result<Vec<u8>, ResParserError> {
    if input.package_id == 0 || input.package_id > 0xff {
        return Err(ResParserError(format!(
            "invalid package id: {}",
            input.package_id
        )));
    }
    if input.package_name.is_empty() {
        return Err(ResParserError("package name is empty".into()));
    }

    // Assign type ids and collect keys / global strings.
    let mut types = input.types.clone();
    for (i, t) in types.iter_mut().enumerate() {
        if t.type_id == 0 {
            t.type_id = (i + 1) as u8;
        }
        if t.configs.is_empty() {
            t.configs.push(ArscBuildConfig::default());
        }
    }

    let mut key_names: Vec<String> = Vec::new();
    let mut key_index: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut global_strings: Vec<String> = Vec::new();
    let mut global_index: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

    let intern_key = |name: &str, key_names: &mut Vec<String>, key_index: &mut std::collections::HashMap<String, u32>| -> u32 {
        if let Some(&i) = key_index.get(name) {
            return i;
        }
        let i = key_names.len() as u32;
        key_names.push(name.to_string());
        key_index.insert(name.to_string(), i);
        i
    };
    let intern_global = |s: &str, global_strings: &mut Vec<String>, global_index: &mut std::collections::HashMap<String, u32>| -> u32 {
        if let Some(&i) = global_index.get(s) {
            return i;
        }
        let i = global_strings.len() as u32;
        global_strings.push(s.to_string());
        global_index.insert(s.to_string(), i);
        i
    };

    for t in &types {
        for cfg in &t.configs {
            for e in &cfg.entries {
                intern_key(&e.name, &mut key_names, &mut key_index);
                if let ArscBuildValue::String(ref s) = e.value {
                    intern_global(s, &mut global_strings, &mut global_index);
                }
            }
        }
    }

    let type_names: Vec<String> = types.iter().map(|t| t.name.clone()).collect();
    let global_pool = encode_string_pool(&global_strings);
    let type_pool = encode_string_pool(&type_names);
    let key_pool = encode_string_pool(&key_names);

    // Build typeSpec + type chunks.
    let mut type_chunks = Vec::new();
    for t in &types {
        type_chunks.extend(build_type_spec(t));
        for cfg in &t.configs {
            type_chunks.extend(build_type_chunk(
                t.type_id,
                cfg,
                &key_index,
                &global_index,
            )?);
        }
    }

    let package = build_package_chunk(
        input.package_id,
        &input.package_name,
        &type_pool,
        &key_pool,
        &type_chunks,
        type_names.len() as u32,
        key_names.len() as u32,
    );

    let table_header_size: u16 = 12;
    let table_size =
        table_header_size as u32 + global_pool.len() as u32 + package.len() as u32;

    let mut out = Vec::with_capacity(table_size as usize);
    out.extend_from_slice(&RES_TABLE_TYPE.to_le_bytes());
    out.extend_from_slice(&table_header_size.to_le_bytes());
    out.extend_from_slice(&table_size.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // packageCount
    out.extend_from_slice(&global_pool);
    out.extend_from_slice(&package);
    Ok(out)
}

fn build_package_chunk(
    pkg_id: u32,
    pkg_name: &str,
    type_pool: &[u8],
    key_pool: &[u8],
    type_chunks: &[u8],
    last_public_type: u32,
    last_public_key: u32,
) -> Vec<u8> {
    let pkg_size =
        PKG_HEADER_SIZE as u32 + type_pool.len() as u32 + key_pool.len() as u32 + type_chunks.len() as u32;
    let mut package = Vec::with_capacity(pkg_size as usize);
    package.extend_from_slice(&RES_TABLE_PACKAGE_TYPE.to_le_bytes());
    package.extend_from_slice(&PKG_HEADER_SIZE.to_le_bytes());
    package.extend_from_slice(&pkg_size.to_le_bytes());
    package.extend_from_slice(&pkg_id.to_le_bytes());

    let mut name = vec![0u8; 256];
    for (i, ch) in pkg_name.encode_utf16().take(127).enumerate() {
        let b = ch.to_le_bytes();
        name[i * 2] = b[0];
        name[i * 2 + 1] = b[1];
    }
    package.extend_from_slice(&name);
    package.extend_from_slice(&(PKG_HEADER_SIZE as u32).to_le_bytes()); // typeStrings
    package.extend_from_slice(&last_public_type.to_le_bytes());
    package.extend_from_slice(&(PKG_HEADER_SIZE as u32 + type_pool.len() as u32).to_le_bytes());
    package.extend_from_slice(&last_public_key.to_le_bytes());
    while package.len() < PKG_HEADER_SIZE as usize {
        package.push(0);
    }
    package.extend_from_slice(type_pool);
    package.extend_from_slice(key_pool);
    package.extend_from_slice(type_chunks);
    package
}

fn build_type_spec(t: &ArscBuildType) -> Vec<u8> {
    let max_entry = t
        .configs
        .iter()
        .flat_map(|c| c.entries.iter())
        .map(|e| e.entry_index as u32)
        .max()
        .unwrap_or(0);
    let entry_count = max_entry + 1;
    let header_size: u16 = 16;
    let size = header_size as u32 + entry_count * 4;
    let mut out = Vec::with_capacity(size as usize);
    out.extend_from_slice(&RES_TABLE_TYPE_SPEC_TYPE.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.push(t.type_id);
    out.push(0);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());

    let mut flags = vec![0u32; entry_count as usize];
    for cfg in &t.configs {
        for e in &cfg.entries {
            let f = if e.public { SPEC_PUBLIC } else { 0 };
            flags[e.entry_index as usize] |= f | SPEC_PUBLIC; // mark present
        }
    }
    for f in flags {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

fn build_type_chunk(
    type_id: u8,
    cfg: &ArscBuildConfig,
    key_index: &std::collections::HashMap<String, u32>,
    global_index: &std::collections::HashMap<String, u32>,
) -> Result<Vec<u8>, ResParserError> {
    let max_entry = cfg
        .entries
        .iter()
        .map(|e| e.entry_index as u32)
        .max()
        .unwrap_or(0);
    let entry_count = if cfg.entries.is_empty() {
        0
    } else {
        max_entry + 1
    };

    let config = cfg
        .raw
        .clone()
        .unwrap_or_else(default_config_bytes);
    let header_size = (8 + 12 + config.len()) as u16;
    let offsets_size = entry_count * 4;
    let entries_start = header_size as u32 + offsets_size;

    // Encode entries first to know sizes.
    let mut entry_blobs: Vec<Option<Vec<u8>>> = vec![None; entry_count as usize];
    for e in &cfg.entries {
        let key = *key_index
            .get(&e.name)
            .ok_or_else(|| ResParserError(format!("missing key {}", e.name)))?;
        let blob = encode_entry(key, &e.value, e.public, global_index)?;
        entry_blobs[e.entry_index as usize] = Some(blob);
    }

    let mut offsets = Vec::with_capacity(entry_count as usize);
    let mut entries_data = Vec::new();
    for blob in &entry_blobs {
        match blob {
            Some(b) => {
                offsets.push(entries_data.len() as u32);
                entries_data.extend_from_slice(b);
                // 4-byte align entries
                while entries_data.len() % 4 != 0 {
                    entries_data.push(0);
                }
            }
            None => offsets.push(NO_ENTRY_32),
        }
    }

    let size = entries_start + entries_data.len() as u32;
    let mut out = Vec::with_capacity(size as usize);
    out.extend_from_slice(&RES_TABLE_TYPE_TYPE.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.push(type_id);
    out.push(0); // flags
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&entries_start.to_le_bytes());
    out.extend_from_slice(&config);
    for off in offsets {
        out.extend_from_slice(&off.to_le_bytes());
    }
    out.extend_from_slice(&entries_data);
    Ok(out)
}

fn encode_entry(
    key: u32,
    value: &ArscBuildValue,
    public: bool,
    global_index: &std::collections::HashMap<String, u32>,
) -> Result<Vec<u8>, ResParserError> {
    let mut flags: u16 = if public { FLAG_PUBLIC } else { 0 };
    match value {
        ArscBuildValue::Bag { parent, items } => {
            flags |= FLAG_COMPLEX;
            let size: u16 = 16; // ResTable_entry + parent + count (complex header)
            let mut out = Vec::new();
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&key.to_le_bytes());
            out.extend_from_slice(&parent.to_le_bytes());
            out.extend_from_slice(&(items.len() as u32).to_le_bytes());
            for (name_id, dt, data) in items {
                out.extend_from_slice(&name_id.to_le_bytes());
                out.extend_from_slice(&8u16.to_le_bytes());
                out.push(0);
                out.push(*dt);
                out.extend_from_slice(&data.to_le_bytes());
            }
            Ok(out)
        }
        other => {
            let (dt, data) = match other {
                ArscBuildValue::Null => (TYPE_NULL, 0u32),
                ArscBuildValue::String(s) => {
                    let idx = *global_index.get(s).ok_or_else(|| {
                        ResParserError(format!("missing global string {s}"))
                    })?;
                    (TYPE_STRING, idx)
                }
                ArscBuildValue::Reference(id) => (TYPE_REFERENCE, *id),
                ArscBuildValue::IntDec(n) => (TYPE_INT_DEC, *n as u32),
                ArscBuildValue::IntHex(n) => (TYPE_INT_HEX, *n),
                ArscBuildValue::Bool(b) => (TYPE_INT_BOOLEAN, if *b { 0xFFFF_FFFF } else { 0 }),
                ArscBuildValue::ColorArgb8(c) => (TYPE_INT_COLOR_ARGB8, *c),
                ArscBuildValue::Raw { data_type, data } => (*data_type, *data),
                ArscBuildValue::Bag { .. } => unreachable!(),
            };
            let size: u16 = 8;
            let mut out = Vec::with_capacity(16);
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&key.to_le_bytes());
            out.extend_from_slice(&8u16.to_le_bytes()); // Res_value.size
            out.push(0);
            out.push(dt);
            out.extend_from_slice(&data.to_le_bytes());
            Ok(out)
        }
    }
}

fn default_config_bytes() -> Vec<u8> {
    let mut c = vec![0u8; CONFIG_SIZE as usize];
    c[0..4].copy_from_slice(&CONFIG_SIZE.to_le_bytes());
    c
}

/// Encode a UTF-16 ResStringPool chunk.
pub fn encode_string_pool(strings: &[String]) -> Vec<u8> {
    let header_size: u16 = 28;
    let string_count = strings.len() as u32;
    let mut offsets = Vec::with_capacity(strings.len());
    let mut data = Vec::new();
    for s in strings {
        offsets.push(data.len() as u32);
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let char_len = utf16.len() as u16;
        data.extend_from_slice(&char_len.to_le_bytes());
        for c in utf16 {
            data.extend_from_slice(&c.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let strings_start = header_size as u32 + string_count * 4;
    let size = strings_start + data.len() as u32;

    let mut out = Vec::new();
    out.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&string_count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // UTF-16
    out.extend_from_slice(&strings_start.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for off in offsets {
        out.extend_from_slice(&off.to_le_bytes());
    }
    out.extend_from_slice(&data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ARSCParser;

    #[test]
    fn build_simple_string_table_roundtrips() {
        let input = ArscBuildInput {
            package_id: 0x7f,
            package_name: "com.example.app".into(),
            types: vec![ArscBuildType {
                name: "string".into(),
                type_id: 1,
                configs: vec![ArscBuildConfig {
                    qualifier: String::new(),
                    raw: None,
                    entries: vec![
                        ArscBuildEntry {
                            entry_index: 0,
                            name: "app_name".into(),
                            value: ArscBuildValue::String("Hello".into()),
                            public: true,
                        },
                        ArscBuildEntry {
                            entry_index: 1,
                            name: "greeting".into(),
                            value: ArscBuildValue::String("Hi".into()),
                            public: true,
                        },
                    ],
                }],
            }],
        };
        let bytes = build_arsc(&input).expect("build");
        let parser = ARSCParser::new(&bytes).expect("parse built arsc");
        assert_eq!(parser.get_packages_names(), vec!["com.example.app".to_string()]);
        let id0 = 0x7f010000u32;
        let id1 = 0x7f010001u32;
        assert_eq!(
            parser.resources.get(&id0).map(|e| e.name.as_str()),
            Some("app_name")
        );
        assert_eq!(
            parser.resources.get(&id0).and_then(|e| e.value.clone()),
            Some("Hello".into())
        );
        assert_eq!(
            parser.resources.get(&id1).and_then(|e| e.value.clone()),
            Some("Hi".into())
        );
    }
}
