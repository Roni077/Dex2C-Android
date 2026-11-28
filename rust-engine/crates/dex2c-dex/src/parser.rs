//! Safe DEX binary parser backed by `androguard/dex-parser` (`dex_parser::DexFile`).
//! Preserves zero-copy ASCII borrowing via `Cow<'_, str>` while delegating MUTF-8
//! surrogate-pair decoding, bounds checking, CodeItem/TryItem parsing, and LEB128
//! decoding directly to `dex-parser`.

use crate::instruction::{CatchHandler, TryCatchBlock};
use dex2c_core::{Dex2cError, Result};
use dex_parser::{CodeItem, DexFile as UpstreamDexFile, NO_INDEX};
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DexHeader {
    pub file_size: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
}

impl From<&dex_parser::DexHeader> for DexHeader {
    fn from(h: &dex_parser::DexHeader) -> Self {
        Self {
            file_size: h.file_size,
            string_ids_size: h.string_ids_size,
            string_ids_off: h.string_ids_off,
            type_ids_size: h.type_ids_size,
            type_ids_off: h.type_ids_off,
            proto_ids_size: h.proto_ids_size,
            proto_ids_off: h.proto_ids_off,
            field_ids_size: h.field_ids_size,
            field_ids_off: h.field_ids_off,
            method_ids_size: h.method_ids_size,
            method_ids_off: h.method_ids_off,
            class_defs_size: h.class_defs_size,
            class_defs_off: h.class_defs_off,
        }
    }
}

/// Owned, `Send + Sync` DEX file accessor backed by `dex_parser::DexFile`.
#[derive(Clone)]
pub struct DexFile {
    pub inner: UpstreamDexFile,
    pub header: DexHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassMethodSummary<'a> {
    pub method_idx: u32,
    pub class_def_idx: u32,
    pub class_idx: u32,
    pub class_desc: &'a str,
    pub method_name: &'a str,
    pub is_init: bool,
    pub code_off: u32,
    pub access_flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DexCodeMeta {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_offset: u32,
    pub insns_count: u32,
    pub insns_offset_bytes: u32,
    pub code_item_offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexFieldMeta<'a> {
    pub field_idx: u32,
    pub access_flags: u32,
    pub name: Cow<'a, str>,
    pub type_desc: Cow<'a, str>,
    pub is_static: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexMethodMeta<'a> {
    pub method_idx: u32,
    pub access_flags: u32,
    pub name: Cow<'a, str>,
    pub shorty: Cow<'a, str>,
    pub return_type: Cow<'a, str>,
    pub param_types: Vec<Cow<'a, str>>,
    pub code_off: u32,
    pub is_direct: bool,
    pub code: Option<DexCodeMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexClassDefFull<'a> {
    pub class_def_idx: u32,
    pub class_idx: u32,
    pub access_flags: u32,
    pub descriptor: Cow<'a, str>,
    pub superclass: Option<Cow<'a, str>>,
    pub source_file: Option<Cow<'a, str>>,
    pub interfaces: Vec<Cow<'a, str>>,
    pub static_fields: Vec<DexFieldMeta<'a>>,
    pub instance_fields: Vec<DexFieldMeta<'a>>,
    pub direct_methods: Vec<DexMethodMeta<'a>>,
    pub virtual_methods: Vec<DexMethodMeta<'a>>,
    pub annotations_off: u32,
    pub static_values_off: u32,
    pub class_data_off: u32,
}

impl DexFile {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let inner = UpstreamDexFile::parse(data)
            .map_err(|e| Dex2cError::DexFormat(e.to_string()))?;
        let header = DexHeader::from(&inner.header);
        Ok(Self { inner, header })
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.inner.data
    }

    #[inline]
    pub fn string_count(&self) -> u32 {
        self.header.string_ids_size
    }

    #[inline]
    pub fn class_def_count(&self) -> u32 {
        self.header.class_defs_size
    }

    pub fn get_string(&self, string_idx: u32) -> Option<Cow<'_, str>> {
        self.inner.strings.get_cow(self.data(), string_idx).ok()
    }

    pub fn get_type_descriptor(&self, type_idx: u32) -> Option<Cow<'_, str>> {
        self.inner
            .types
            .get_cow(self.data(), &self.inner.strings, type_idx)
            .ok()
    }

    pub fn get_proto(&self, proto_idx: u32) -> Option<(Cow<'_, str>, Cow<'_, str>, Vec<Cow<'_, str>>)> {
        self.inner
            .protos
            .get_proto_cow(self.data(), &self.inner.types, &self.inner.strings, proto_idx)
            .ok()
    }

    pub fn get_method_name(&self, method_idx: u32) -> Option<Cow<'_, str>> {
        let m = self.inner.methods.get(method_idx).ok()?;
        self.get_string(m.name_idx)
    }

    pub fn get_method_class_desc(&self, method_idx: u32) -> Option<Cow<'_, str>> {
        let m = self.inner.methods.get(method_idx).ok()?;
        self.get_type_descriptor(m.class_idx as u32)
    }

    pub fn get_method_proto(&self, method_idx: u32) -> Option<(Cow<'_, str>, Cow<'_, str>, Vec<Cow<'_, str>>)> {
        let m = self.inner.methods.get(method_idx).ok()?;
        self.get_proto(m.proto_idx as u32)
    }

    pub fn get_field_info(&self, field_idx: u32) -> Option<(Cow<'_, str>, Cow<'_, str>)> {
        let f = self.inner.fields.get(field_idx).ok()?;
        let name = self.get_string(f.name_idx)?;
        let type_desc = self.get_type_descriptor(f.type_idx as u32)?;
        Some((name, type_desc))
    }

    pub fn get_field_full(&self, field_idx: u32) -> Option<(Cow<'_, str>, Cow<'_, str>, Cow<'_, str>)> {
        let f = self.inner.fields.get(field_idx).ok()?;
        let class_desc = self.get_type_descriptor(f.class_idx as u32)?;
        let name = self.get_string(f.name_idx)?;
        let type_desc = self.get_type_descriptor(f.type_idx as u32)?;
        Some((class_desc, name, type_desc))
    }

    pub fn get_code_meta(&self, code_off: u32) -> Option<DexCodeMeta> {
        if code_off == 0 {
            return None;
        }
        let item = CodeItem::parse(self.data(), code_off).ok()?;
        Some(DexCodeMeta {
            registers_size: item.registers_size,
            ins_size: item.ins_size,
            outs_size: item.outs_size,
            tries_size: item.tries_size,
            debug_info_offset: item.debug_info_off,
            insns_count: item.insns_size,
            insns_offset_bytes: item.insns_off as u32,
            code_item_offset: item.code_off,
        })
    }

    /// Safe instruction byte slice for `meta`.
    pub fn get_insns_bytes(&self, meta: &DexCodeMeta) -> Option<&[u8]> {
        let start = meta.insns_offset_bytes as usize;
        let byte_len = (meta.insns_count as usize).checked_mul(2)?;
        let end = start.checked_add(byte_len)?;
        self.data().get(start..end)
    }

    /// Safe aligned `Vec<u16>` instruction code units (avoids unaligned raw pointer casts).
    pub fn get_insns_units(&self, meta: &DexCodeMeta) -> Option<Vec<u16>> {
        let bytes = self.get_insns_bytes(meta)?;
        Some(
            bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect(),
        )
    }

    pub fn get_try_blocks(&self, code_off: u32) -> Vec<TryCatchBlock> {
        if code_off == 0 {
            return Vec::new();
        }
        let Ok(code) = CodeItem::parse(self.data(), code_off) else {
            return Vec::new();
        };
        let Ok(tries) = code.tries(self.data()) else {
            return Vec::new();
        };
        tries
            .into_iter()
            .map(|t| {
                let mut handlers = Vec::with_capacity(t.handlers.len());
                let mut catch_all_pc = None;
                for (type_idx_opt, addr) in t.handlers {
                    if let Some(t_idx) = type_idx_opt {
                        let desc = self
                            .get_type_descriptor(t_idx)
                            .map(|c| c.into_owned())
                            .unwrap_or_else(|| format!("type@{t_idx}"));
                        handlers.push(CatchHandler {
                            type_desc: Some(desc),
                            handler_pc: addr,
                        });
                    } else {
                        catch_all_pc = Some(addr);
                        handlers.push(CatchHandler {
                            type_desc: None,
                            handler_pc: addr,
                        });
                    }
                }
                TryCatchBlock {
                    start_pc: t.start_unit,
                    end_pc: t.start_unit.saturating_add(t.insn_count as u32),
                    insn_count: t.insn_count,
                    handlers,
                    catch_all_pc,
                }
            })
            .collect()
    }

    pub fn get_class_def_full(&self, class_def_idx: u32) -> Option<DexClassDefFull<'_>> {
        let cd = self.inner.get_class_def(class_def_idx).ok()?;
        let descriptor = self.get_type_descriptor(cd.class_idx)?;

        let superclass = if cd.superclass_idx != NO_INDEX {
            self.get_type_descriptor(cd.superclass_idx)
        } else {
            None
        };

        let source_file = if cd.source_file_idx != NO_INDEX {
            self.get_string(cd.source_file_idx)
        } else {
            None
        };

        let interfaces = self.parse_interfaces_cow(cd.interfaces_off);

        let mut static_fields = Vec::new();
        let mut instance_fields = Vec::new();
        let mut direct_methods = Vec::new();
        let mut virtual_methods = Vec::new();

        if let Ok(Some(class_data)) = self.inner.get_class_data(&cd) {
            static_fields.reserve_exact(class_data.static_fields.len());
            for f in class_data.static_fields {
                if let Some((name, type_desc)) = self.get_field_info(f.field_idx) {
                    static_fields.push(DexFieldMeta {
                        field_idx: f.field_idx,
                        access_flags: f.access_flags,
                        name,
                        type_desc,
                        is_static: true,
                    });
                }
            }

            instance_fields.reserve_exact(class_data.instance_fields.len());
            for f in class_data.instance_fields {
                if let Some((name, type_desc)) = self.get_field_info(f.field_idx) {
                    instance_fields.push(DexFieldMeta {
                        field_idx: f.field_idx,
                        access_flags: f.access_flags,
                        name,
                        type_desc,
                        is_static: false,
                    });
                }
            }

            direct_methods.reserve_exact(class_data.direct_methods.len());
            for m in class_data.direct_methods {
                let name = self.get_method_name(m.method_idx).unwrap_or(Cow::Borrowed("unknown"));
                let (shorty, return_type, param_types) = self
                    .get_method_proto(m.method_idx)
                    .unwrap_or_else(|| (Cow::Borrowed("V"), Cow::Borrowed("V"), Vec::new()));
                let code = self.get_code_meta(m.code_off);
                direct_methods.push(DexMethodMeta {
                    method_idx: m.method_idx,
                    access_flags: m.access_flags,
                    name,
                    shorty,
                    return_type,
                    param_types,
                    code_off: m.code_off,
                    is_direct: true,
                    code,
                });
            }

            virtual_methods.reserve_exact(class_data.virtual_methods.len());
            for m in class_data.virtual_methods {
                let name = self.get_method_name(m.method_idx).unwrap_or(Cow::Borrowed("unknown"));
                let (shorty, return_type, param_types) = self
                    .get_method_proto(m.method_idx)
                    .unwrap_or_else(|| (Cow::Borrowed("V"), Cow::Borrowed("V"), Vec::new()));
                let code = self.get_code_meta(m.code_off);
                virtual_methods.push(DexMethodMeta {
                    method_idx: m.method_idx,
                    access_flags: m.access_flags,
                    name,
                    shorty,
                    return_type,
                    param_types,
                    code_off: m.code_off,
                    is_direct: false,
                    code,
                });
            }
        }

        Some(DexClassDefFull {
            class_def_idx,
            class_idx: cd.class_idx,
            access_flags: cd.access_flags,
            descriptor,
            superclass,
            source_file,
            interfaces,
            static_fields,
            instance_fields,
            direct_methods,
            virtual_methods,
            annotations_off: cd.annotations_off,
            static_values_off: cd.static_values_off,
            class_data_off: cd.class_data_off,
        })
    }

    fn parse_interfaces_cow(&self, interfaces_off: u32) -> Vec<Cow<'_, str>> {
        if interfaces_off == 0 {
            return Vec::new();
        }
        let off = interfaces_off as usize;
        let data = self.data();
        if off + 4 > data.len() {
            return Vec::new();
        }
        let size = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as usize;
        let end = match dex_parser::table_end(off + 4, size, 2, "interfaces type_list") {
            Ok(e) if e <= data.len() => e,
            _ => return Vec::new(),
        };
        let _ = end;
        let mut out = Vec::with_capacity(size);
        for i in 0..size {
            let p = off + 4 + i * 2;
            let idx = u16::from_le_bytes([data[p], data[p + 1]]) as u32;
            if let Some(desc) = self.get_type_descriptor(idx) {
                out.push(desc);
            }
        }
        out
    }

    /// Fast streaming method iterator for SIMD filtering without constructing intermediate class trees.
    pub fn for_each_method<F>(&self, mut callback: F)
    where
        F: FnMut(ClassMethodSummary<'_>),
    {
        for class_def_idx in 0..self.header.class_defs_size {
            let Ok(cd) = self.inner.get_class_def(class_def_idx) else {
                continue;
            };
            let Some(class_desc_cow) = self.get_type_descriptor(cd.class_idx) else {
                continue;
            };
            let Ok(Some(class_data)) = self.inner.get_class_data(&cd) else {
                continue;
            };

            let class_desc: &str = class_desc_cow.as_ref();
            for m in class_data
                .direct_methods
                .iter()
                .chain(class_data.virtual_methods.iter())
            {
                if let Some(m_name_cow) = self.get_method_name(m.method_idx) {
                    let method_name: &str = m_name_cow.as_ref();
                    let is_init = method_name == "<init>";
                    callback(ClassMethodSummary {
                        method_idx: m.method_idx,
                        class_def_idx,
                        class_idx: cd.class_idx,
                        class_desc,
                        method_name,
                        is_init,
                        code_off: m.code_off,
                        access_flags: m.access_flags,
                    });
                }
            }
        }
    }
}
