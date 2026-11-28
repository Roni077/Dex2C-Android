//! Dalvik bytecode instruction decoder powered by `androguard/dex-bytecode`.
//! Supports all standard Dalvik opcodes (formats `F10x`..`F5rc`) and payload
//! pseudo-instructions (`0x0100` packed-switch, `0x0200` sparse-switch, `0x0300` fill-array-data).

use crate::instruction::{DalvikInstruction, DalvikPayload, OpcodeGroup};
use crate::parser::{DexCodeMeta, DexFile};
use dex_bytecode::{
    decode_one_with_resolver, decode_raw_one, get_opcode_entry, get_payload_kind, Format,
    PayloadKind, RefKind, ResolveRef,
};
use std::collections::HashMap;
use std::fmt::Write as _;

pub struct DalvikDisassembler<'a> {
    pub dex: &'a DexFile,
}

struct DexRefResolver<'a> {
    dex: &'a DexFile,
}

impl ResolveRef for DexRefResolver<'_> {
    fn resolve(&self, kind: RefKind, index: u32) -> Option<String> {
        match kind {
            RefKind::String => {
                let s = self.dex.get_string(index)?;
                Some(format!("\"{}\"", truncate_and_escape(&s, 48)))
            }
            RefKind::Type => self.dex.get_type_descriptor(index).map(|c| c.into_owned()),
            RefKind::Field => {
                let (cls, name, typ) = self.dex.get_field_full(index)?;
                Some(format!("{}->{}:{}", cls, name, typ))
            }
            RefKind::Method => {
                let cls = self.dex.get_method_class_desc(index)?;
                let name = self.dex.get_method_name(index)?;
                let (_, ret, params) = self.dex.get_method_proto(index)?;
                Some(format!("{}->{}({}){}", cls, name, params.join(""), ret))
            }
            RefKind::MethodProto => {
                let (_, ret, params) = self.dex.get_proto(index)?;
                Some(format!("({}){}", params.join(""), ret))
            }
            RefKind::CallSite => self.dex.inner.get_call_site(index).ok().map(|cs| {
                format!("call_site@{}#{}", index, cs.method_name)
            }),
            _ => None,
        }
    }
}

impl<'a> DalvikDisassembler<'a> {
    pub fn new(dex: &'a DexFile) -> Self {
        Self { dex }
    }

    pub fn disassemble_method(&self, meta: &DexCodeMeta) -> Vec<DalvikInstruction> {
        match self.dex.get_insns_bytes(meta) {
            Some(bytes) => self.disassemble_bytes(bytes),
            None => Vec::new(),
        }
    }

    pub fn disassemble_code(&self, code_units: &[u16]) -> Vec<DalvikInstruction> {
        let mut bytes = Vec::with_capacity(code_units.len() * 2);
        for &u in code_units {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        self.disassemble_bytes(&bytes)
    }

    pub fn disassemble_bytes(&self, code_bytes: &[u8]) -> Vec<DalvikInstruction> {
        if code_bytes.len() < 2 {
            return Vec::new();
        }

        let resolver = DexRefResolver { dex: self.dex };
        let mut out = Vec::with_capacity(code_bytes.len() / 2);
        let mut byte_off = 0usize;

        while byte_off + 1 < code_bytes.len() {
            let unit = u16::from_le_bytes([code_bytes[byte_off], code_bytes[byte_off + 1]]);
            let word_off = (byte_off / 2) as u32;

            // 1. Handle payload pseudo-instructions (0x0100 / 0x0200 / 0x0300)
            let is_payload_candidate =
                unit > 0xFF && ((unit & 0xFF) == 0x00 || (unit & 0xFF) == 0xFF);
            if is_payload_candidate {
                if let Some(kind) = get_payload_kind(unit) {
                    if let (Ok(raw), Ok(dec)) = (
                        decode_raw_one(code_bytes, byte_off),
                        decode_one_with_resolver(code_bytes, byte_off, &resolver),
                    ) {
                        let len_bytes = (raw.length as usize).max(2);
                        let len_units = (len_bytes / 2).max(1) as u16;
                        let preview_words = read_raw_words(code_bytes, byte_off, len_units.min(4) as usize);
                        let placeholder_op = match kind {
                            PayloadKind::PackedSwitch => {
                                let size = read_u16_le(code_bytes, byte_off + 2).unwrap_or(0);
                                format!("{size} targets")
                            }
                            PayloadKind::SparseSwitch => {
                                let size = read_u16_le(code_bytes, byte_off + 2).unwrap_or(0);
                                format!("{size} cases")
                            }
                            PayloadKind::FillArrayData => {
                                let ew = read_u16_le(code_bytes, byte_off + 2).unwrap_or(0);
                                let sz = read_u32_le(code_bytes, byte_off + 4).unwrap_or(0);
                                format!("{ew}B x {sz}")
                            }
                        };
                        out.push(DalvikInstruction {
                            offset: word_off,
                            opcode: unit,
                            mnemonic: dec.mnemonic,
                            format: "payload",
                            operands_text: placeholder_op,
                            raw_words: preview_words,
                            group: OpcodeGroup::Payload,
                            length_units: len_units,
                            registers: Vec::new(),
                            literal: None,
                            target_offset: None,
                            index: None,
                            payload: None,
                        });
                        byte_off += len_bytes;
                        continue;
                    }
                }
            }

            // 2. Standard instruction decode via dex-bytecode
            if let Ok(raw) = decode_raw_one(code_bytes, byte_off) {
                let entry = get_opcode_entry(raw.opcode);
                let len_bytes = (raw.length as usize).max(2);
                let len_units = (len_bytes / 2).max(1) as u16;
                let raw_words = read_raw_words(code_bytes, byte_off, len_units as usize);
                let operands_text = decode_one_with_resolver(code_bytes, byte_off, &resolver)
                    .map(|ins| ins.operands)
                    .unwrap_or_default();

                let registers = extract_all_registers(code_bytes, byte_off, &raw);
                let literal = if has_literal_format(raw.format) {
                    Some(raw.literal)
                } else {
                    None
                };
                let target_offset = if has_branch_format(raw.format) {
                    Some(raw.branch)
                } else {
                    None
                };
                let index = if raw.ref_kind != RefKind::None {
                    Some(raw.index)
                } else {
                    None
                };
                let group = classify_opcode_group(raw.opcode, raw.format);

                out.push(DalvikInstruction {
                    offset: word_off,
                    opcode: unit,
                    mnemonic: entry.mnemonic,
                    format: format_label(raw.format),
                    operands_text,
                    raw_words,
                    group,
                    length_units: len_units,
                    registers,
                    literal,
                    target_offset,
                    index,
                    payload: None,
                });
                byte_off += len_bytes;
            } else {
                // Unknown/corrupt single code-unit fallback
                let op_byte = (unit & 0xFF) as u8;
                let entry = get_opcode_entry(op_byte);
                let raw_words = read_raw_words(code_bytes, byte_off, 1);
                out.push(DalvikInstruction {
                    offset: word_off,
                    opcode: unit,
                    mnemonic: entry.mnemonic,
                    format: "10x",
                    operands_text: String::new(),
                    raw_words,
                    group: OpcodeGroup::Unknown,
                    length_units: 1,
                    registers: Vec::new(),
                    literal: None,
                    target_offset: None,
                    index: None,
                    payload: None,
                });
                byte_off += 2;
            }
        }

        Self::link_and_decode_payloads(&mut out, code_bytes);
        out
    }

    fn link_and_decode_payloads(insns: &mut [DalvikInstruction], code_bytes: &[u8]) {
        // Record referrer instruction word offset for each payload word offset
        let mut referrer_by_payload_word: HashMap<u32, i32> = HashMap::new();
        for insn in insns.iter() {
            let op = (insn.opcode & 0xFF) as u8;
            if matches!(op, 0x26 | 0x2B | 0x2C) {
                if let Some(rel_words) = insn.target_offset {
                    let payload_word = insn.offset as i32 + rel_words;
                    if payload_word >= 0 {
                        referrer_by_payload_word
                            .entry(payload_word as u32)
                            .or_insert(insn.offset as i32);
                    }
                }
            }
        }

        let mut decoded_payloads: HashMap<u32, (DalvikPayload, String)> = HashMap::new();
        for insn in insns.iter() {
            if insn.group != OpcodeGroup::Payload {
                continue;
            }
            let p_word = insn.offset;
            let p_byte = (p_word as usize) * 2;
            let base_pc = *referrer_by_payload_word
                .get(&p_word)
                .unwrap_or(&(p_word as i32));

            match insn.opcode {
                0x0100 => {
                    let size = read_u16_le(code_bytes, p_byte + 2).unwrap_or(0) as usize;
                    let first_key = read_i32_le(code_bytes, p_byte + 4).unwrap_or(0);
                    let mut targets = Vec::with_capacity(size);
                    for i in 0..size {
                        if let Some(rel) = read_i32_le(code_bytes, p_byte + 8 + i * 4) {
                            targets.push(base_pc + rel);
                        }
                    }
                    let summary = if targets.is_empty() {
                        "0 targets".to_string()
                    } else {
                        let preview: Vec<String> = targets
                            .iter()
                            .take(4)
                            .enumerate()
                            .map(|(i, tgt)| format!("{}->L_{:04x}", first_key + i as i32, tgt))
                            .collect();
                        let ellipsis = if targets.len() > 4 { ", …" } else { "" };
                        format!("first={} [{}{}]", first_key, preview.join(", "), ellipsis)
                    };
                    decoded_payloads.insert(
                        p_word,
                        (
                            DalvikPayload::PackedSwitch {
                                offset_words: p_word,
                                word_count: insn.length_units,
                                first_key,
                                targets,
                            },
                            summary,
                        ),
                    );
                }
                0x0200 => {
                    let size = read_u16_le(code_bytes, p_byte + 2).unwrap_or(0) as usize;
                    let mut keys = Vec::with_capacity(size);
                    let mut targets = Vec::with_capacity(size);
                    for i in 0..size {
                        if let (Some(k), Some(rel)) = (
                            read_i32_le(code_bytes, p_byte + 4 + i * 4),
                            read_i32_le(code_bytes, p_byte + 4 + size * 4 + i * 4),
                        ) {
                            keys.push(k);
                            targets.push(base_pc + rel);
                        }
                    }
                    let summary = if keys.is_empty() {
                        "0 cases".to_string()
                    } else {
                        let preview: Vec<String> = keys
                            .iter()
                            .zip(targets.iter())
                            .take(4)
                            .map(|(k, tgt)| format!("{}->L_{:04x}", k, tgt))
                            .collect();
                        let ellipsis = if keys.len() > 4 { ", …" } else { "" };
                        format!("{} cases [{}{}]", keys.len(), preview.join(", "), ellipsis)
                    };
                    decoded_payloads.insert(
                        p_word,
                        (
                            DalvikPayload::SparseSwitch {
                                offset_words: p_word,
                                word_count: insn.length_units,
                                keys,
                                targets,
                            },
                            summary,
                        ),
                    );
                }
                0x0300 => {
                    let elem_width = read_u16_le(code_bytes, p_byte + 2).unwrap_or(1).max(1);
                    let elem_count = read_u32_le(code_bytes, p_byte + 4).unwrap_or(0);
                    let data_start = p_byte + 8;
                    let total_bytes = (elem_count as usize)
                        .saturating_mul(elem_width as usize)
                        .min(4096);
                    let available = code_bytes.len().saturating_sub(data_start);
                    let safe_len = total_bytes.min(available);
                    let data_slice = &code_bytes[data_start..data_start + safe_len];

                    let mut preview_elements = Vec::new();
                    let w = elem_width as usize;
                    for i in 0..(elem_count as usize).min(12) {
                        let start = i * w;
                        if start + w > data_slice.len() {
                            break;
                        }
                        let formatted = match w {
                            1 => (data_slice[start] as i8).to_string(),
                            2 => i16::from_le_bytes([data_slice[start], data_slice[start + 1]])
                                .to_string(),
                            4 => i32::from_le_bytes([
                                data_slice[start],
                                data_slice[start + 1],
                                data_slice[start + 2],
                                data_slice[start + 3],
                            ])
                            .to_string(),
                            8 => i64::from_le_bytes([
                                data_slice[start],
                                data_slice[start + 1],
                                data_slice[start + 2],
                                data_slice[start + 3],
                                data_slice[start + 4],
                                data_slice[start + 5],
                                data_slice[start + 6],
                                data_slice[start + 7],
                            ])
                            .to_string(),
                            _ => format!("0x{:02X}", data_slice[start]),
                        };
                        preview_elements.push(formatted);
                    }

                    let hex_count = safe_len.min(16);
                    let mut hex_preview = String::new();
                    for (i, b) in data_slice[..hex_count].iter().enumerate() {
                        if i > 0 {
                            hex_preview.push(' ');
                        }
                        let _ = write!(hex_preview, "{:02X}", b);
                    }
                    if safe_len > 16 {
                        hex_preview.push_str(" …");
                    }
                    let summary = if preview_elements.is_empty() {
                        format!("{elem_width}B × {elem_count}")
                    } else {
                        let vals: Vec<&str> =
                            preview_elements.iter().take(6).map(String::as_str).collect();
                        let ellipsis = if elem_count > 6 { ", …" } else { "" };
                        format!("{elem_width}B × {elem_count} [{}{}]", vals.join(", "), ellipsis)
                    };

                    decoded_payloads.insert(
                        p_word,
                        (
                            DalvikPayload::FillArrayData {
                                offset_words: p_word,
                                word_count: insn.length_units,
                                element_width: elem_width,
                                element_count: elem_count,
                                data: data_slice.to_vec(),
                                preview_elements,
                                hex_preview,
                            },
                            summary,
                        ),
                    );
                }
                _ => {}
            }
        }

        for insn in insns.iter_mut() {
            if insn.group == OpcodeGroup::Payload {
                if let Some((payload, summary)) = decoded_payloads.get(&insn.offset) {
                    insn.payload = Some(payload.clone());
                    insn.operands_text = summary.clone();
                }
            } else if matches!((insn.opcode & 0xFF) as u8, 0x26 | 0x2B | 0x2C) {
                if let Some(rel) = insn.target_offset {
                    let target_word = insn.offset as i32 + rel;
                    if target_word >= 0 {
                        if let Some((payload, _)) = decoded_payloads.get(&(target_word as u32)) {
                            insn.payload = Some(payload.clone());
                        }
                    }
                }
            }
        }
    }
}

fn extract_all_registers(
    code_bytes: &[u8],
    byte_off: usize,
    raw: &dex_bytecode::RawInsn,
) -> Vec<u16> {
    match raw.format {
        Format::F3rc | Format::F3rmi | Format::F3rms | Format::F4rcc => {
            let count = code_bytes.get(byte_off + 1).copied().unwrap_or(0) as usize;
            let start = read_u16_le(code_bytes, byte_off + 4).unwrap_or(0);
            (0..count).map(|k| start.saturating_add(k as u16)).collect()
        }
        Format::F5rc => {
            let count = read_u16_le(code_bytes, byte_off + 6).unwrap_or(0) as usize;
            let start = read_u16_le(code_bytes, byte_off + 8).unwrap_or(0);
            (0..count.min(256))
                .map(|k| start.saturating_add(k as u16))
                .collect()
        }
        _ => raw.regs[..raw.reg_count as usize].to_vec(),
    }
}

fn has_literal_format(fmt: Format) -> bool {
    matches!(
        fmt,
        Format::F11n | Format::F21s | Format::F21h | Format::F22b | Format::F22s | Format::F31i | Format::F51l
    )
}

fn has_branch_format(fmt: Format) -> bool {
    matches!(
        fmt,
        Format::F10t | Format::F20t | Format::F21t | Format::F22t | Format::F30t | Format::F31t
    )
}

fn format_label(fmt: Format) -> &'static str {
    match fmt {
        Format::F00x => "00x",
        Format::F10x => "10x",
        Format::F10t => "10t",
        Format::F11n => "11n",
        Format::F11x => "11x",
        Format::F12x => "12x",
        Format::F20t => "20t",
        Format::F20bc => "20bc",
        Format::F21c => "21c",
        Format::F21h => "21h",
        Format::F21s => "21s",
        Format::F21t => "21t",
        Format::F22b => "22b",
        Format::F22x => "22x",
        Format::F22c => "22c",
        Format::F22s => "22s",
        Format::F22t => "22t",
        Format::F22cs => "22cs",
        Format::F23x => "23x",
        Format::F30t => "30t",
        Format::F31c => "31c",
        Format::F31i => "31i",
        Format::F31t => "31t",
        Format::F32x => "32x",
        Format::F35c | Format::F35mi | Format::F35ms => "35c",
        Format::F3rc | Format::F3rmi | Format::F3rms => "3rc",
        Format::F40sc => "40sc",
        Format::F41c => "41c",
        Format::F45cc => "45cc",
        Format::F4rcc => "4rcc",
        Format::F51l => "51l",
        Format::F52c => "52c",
        Format::F5rc => "5rc",
    }
}

pub fn classify_opcode_group(opcode: u8, format: Format) -> OpcodeGroup {
    if format == Format::F00x {
        return OpcodeGroup::Unknown;
    }
    match opcode {
        0x00 => OpcodeGroup::Nop,
        0x01..=0x0D => OpcodeGroup::Move,
        0x0E..=0x11 => OpcodeGroup::Return,
        0x12..=0x1C | 0xFE..=0xFF => OpcodeGroup::Const,
        0x1D..=0x1E => OpcodeGroup::Monitor,
        0x1F => OpcodeGroup::CheckCast,
        0x20 => OpcodeGroup::InstanceOf,
        0x21 => OpcodeGroup::ArrayLength,
        0x22 => OpcodeGroup::NewInstance,
        0x23 => OpcodeGroup::NewArray,
        0x24..=0x25 => OpcodeGroup::FilledNewArray,
        0x26 => OpcodeGroup::FillArrayData,
        0x27 => OpcodeGroup::Throw,
        0x28..=0x2A => OpcodeGroup::Goto,
        0x2B => OpcodeGroup::PackedSwitch,
        0x2C => OpcodeGroup::SparseSwitch,
        0x2D..=0x31 => OpcodeGroup::Cmp,
        0x32..=0x37 => OpcodeGroup::IfTest,
        0x38..=0x3D => OpcodeGroup::IfTestZ,
        0x44..=0x4A => OpcodeGroup::ArrayGet,
        0x4B..=0x51 => OpcodeGroup::ArrayPut,
        0x52..=0x58 => OpcodeGroup::InstanceFieldGet,
        0x59..=0x5F => OpcodeGroup::InstanceFieldPut,
        0x60..=0x66 => OpcodeGroup::StaticFieldGet,
        0x67..=0x6D => OpcodeGroup::StaticFieldPut,
        0x6E => OpcodeGroup::InvokeVirtual,
        0x6F => OpcodeGroup::InvokeSuper,
        0x70 => OpcodeGroup::InvokeDirect,
        0x71 => OpcodeGroup::InvokeStatic,
        0x72 => OpcodeGroup::InvokeInterface,
        0x74 => OpcodeGroup::InvokeVirtualRange,
        0x75 => OpcodeGroup::InvokeSuperRange,
        0x76 => OpcodeGroup::InvokeDirectRange,
        0x77 => OpcodeGroup::InvokeStaticRange,
        0x78 => OpcodeGroup::InvokeInterfaceRange,
        0x7B..=0x8F => OpcodeGroup::Unop,
        0x90..=0xAF => OpcodeGroup::Binop,
        0xB0..=0xCF => OpcodeGroup::Binop2Addr,
        0xD0..=0xD7 => OpcodeGroup::BinopLit16,
        0xD8..=0xE2 => OpcodeGroup::BinopLit8,
        0xFA => OpcodeGroup::InvokePolymorphic,
        0xFB => OpcodeGroup::InvokePolymorphicRange,
        0xFC => OpcodeGroup::InvokeCustom,
        0xFD => OpcodeGroup::InvokeCustomRange,
        _ => OpcodeGroup::Unknown,
    }
}

fn read_raw_words(code_bytes: &[u8], byte_off: usize, max_words: usize) -> Vec<u16> {
    let mut words = Vec::with_capacity(max_words);
    for i in 0..max_words {
        if let Some(w) = read_u16_le(code_bytes, byte_off + i * 2) {
            words.push(w);
        }
    }
    words
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_i32_le(data: &[u8], off: usize) -> Option<i32> {
    read_u32_le(data, off).map(|u| u as i32)
}

fn truncate_and_escape(s: &str, max_chars: usize) -> String {
    let escaped = s
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('"', "\\\"");
    if escaped.chars().count() > max_chars {
        let mut out: String = escaped.chars().take(max_chars.saturating_sub(3)).collect();
        out.push_str("...");
        out
    } else {
        escaped
    }
}
