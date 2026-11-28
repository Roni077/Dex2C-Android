//! Pre-flight Dalvik structural & `RegType` bytecode verifier.
//! Validates register bounds, wide pairs, pool indices, instruction boundaries,
//! branch/switch/try-catch targets, return types, and forward abstract-interpretation
//! register types before DEX edits are committed.

use crate::cfg::MethodCfg;
use crate::disassembler::DalvikDisassembler;
use crate::instruction::{DalvikInstruction, DalvikPayload, OpcodeGroup};
use crate::parser::{DexClassDefFull, DexFile, DexMethodMeta};
use dex_bytecode::{get_opcode_entry, Format, RefKind};
use serde::Serialize;
use std::collections::{HashSet, VecDeque};

const ACC_STATIC: u32 = 0x0008;
const ACC_NATIVE: u32 = 0x0100;
const ACC_ABSTRACT: u32 = 0x0400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegType {
    Undefined,
    ZeroOrNull,
    Primitive32,
    WideLo,
    WideHi,
    Reference,
    UninitializedThis,
    UninitializedNew(u32),
    Conflict,
}

impl RegType {
    fn join(a: &RegType, b: &RegType) -> RegType {
        if a == b {
            return a.clone();
        }
        match (a, b) {
            (RegType::Undefined, other) | (other, RegType::Undefined) => other.clone(),
            (RegType::Conflict, _) | (_, RegType::Conflict) => RegType::Conflict,
            (RegType::ZeroOrNull, RegType::Primitive32)
            | (RegType::Primitive32, RegType::ZeroOrNull) => RegType::Primitive32,
            (RegType::ZeroOrNull, RegType::Reference)
            | (RegType::Reference, RegType::ZeroOrNull) => RegType::Reference,
            _ => RegType::Conflict,
        }
    }

    fn is_prim32(&self) -> bool {
        matches!(self, RegType::ZeroOrNull | RegType::Primitive32)
    }

    fn is_ref_or_null(&self) -> bool {
        matches!(self, RegType::ZeroOrNull | RegType::Reference)
    }

    fn is_any_ref(&self) -> bool {
        matches!(
            self,
            RegType::ZeroOrNull
                | RegType::Reference
                | RegType::UninitializedThis
                | RegType::UninitializedNew(_)
        )
    }

    fn is_wide_pair(lo: &RegType, hi: &RegType) -> bool {
        *lo == RegType::WideLo && *hi == RegType::WideHi
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodVerificationIssue {
    pub pc_word: u32,
    pub mnemonic: String,
    pub severity: &'static str,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodVerificationReport {
    pub passed: bool,
    pub class_descriptor: String,
    pub method_idx: u32,
    pub method_name: String,
    pub registers_size: u16,
    pub ins_size: u16,
    pub instruction_count: usize,
    pub issues: Vec<MethodVerificationIssue>,
}

/// Verifies a single method by `class_def_idx` and `method_idx`.
pub fn verify_dex_method(
    dex: &DexFile,
    class_def_idx: u32,
    method_idx: u32,
) -> Option<MethodVerificationReport> {
    let cls = dex.get_class_def_full(class_def_idx)?;
    let method = cls
        .direct_methods
        .iter()
        .chain(cls.virtual_methods.iter())
        .find(|m| m.method_idx == method_idx)?;
    Some(verify_method_meta(dex, &cls, method))
}

/// Verifies every method in `class_def_idx` and returns reports (failing methods first).
pub fn verify_dex_class(dex: &DexFile, class_def_idx: u32) -> Option<Vec<MethodVerificationReport>> {
    let cls = dex.get_class_def_full(class_def_idx)?;
    let mut reports: Vec<MethodVerificationReport> = cls
        .direct_methods
        .iter()
        .chain(cls.virtual_methods.iter())
        .map(|m| verify_method_meta(dex, &cls, m))
        .collect();
    reports.sort_by_key(|r| r.passed);
    Some(reports)
}

pub fn verify_method_meta(
    dex: &DexFile,
    cls: &DexClassDefFull<'_>,
    method: &DexMethodMeta<'_>,
) -> MethodVerificationReport {
    let mut issues = Vec::new();
    let class_descriptor = cls.descriptor.to_string();
    let method_name = method.name.to_string();

    let Some(code) = method.code else {
        if (method.access_flags & (ACC_NATIVE | ACC_ABSTRACT)) == 0 {
            issues.push(issue(
                0,
                "<method>",
                "NO_CODE",
                "Non-native, non-abstract method is missing a code_item body",
            ));
        }
        return MethodVerificationReport {
            passed: issues.is_empty(),
            class_descriptor,
            method_idx: method.method_idx,
            method_name,
            registers_size: 0,
            ins_size: 0,
            instruction_count: 0,
            issues,
        };
    };

    if code.registers_size < code.ins_size {
        issues.push(issue(
            0,
            "<code_item>",
            "BAD_REG_COUNT",
            format!(
                "ins_size ({}) exceeds registers_size ({})",
                code.ins_size, code.registers_size
            ),
        ));
    }

    let Some(code_bytes) = dex.get_insns_bytes(&code) else {
        issues.push(issue(
            0,
            "<code_item>",
            "TRUNCATED_CODE",
            "Instruction array extends past end of DEX buffer",
        ));
        return MethodVerificationReport {
            passed: false,
            class_descriptor,
            method_idx: method.method_idx,
            method_name,
            registers_size: code.registers_size,
            ins_size: code.ins_size,
            instruction_count: 0,
            issues,
        };
    };

    if code.insns_count == 0 || code_bytes.len() < 2 {
        issues.push(issue(
            0,
            "<code_item>",
            "EMPTY_CODE",
            "Method bytecode body cannot be empty",
        ));
        return MethodVerificationReport {
            passed: false,
            class_descriptor,
            method_idx: method.method_idx,
            method_name,
            registers_size: code.registers_size,
            ins_size: code.ins_size,
            instruction_count: 0,
            issues,
        };
    }

    let disasm = DalvikDisassembler::new(dex);
    let insns = disasm.disassemble_bytes(code_bytes);
    let tries = dex.get_try_blocks(code.code_item_offset);

    // Check total decoded coverage against insns_count & instruction boundaries.
    let mut exec_offsets = HashSet::new();
    let mut payload_offsets = HashSet::new();
    let mut covered_words = 0u32;
    for insn in &insns {
        covered_words = covered_words.max(insn.offset + insn.length_units as u32);
        if insn.group == OpcodeGroup::Payload {
            payload_offsets.insert(insn.offset);
        } else {
            exec_offsets.insert(insn.offset);
            if insn.group == OpcodeGroup::Unknown {
                issues.push(issue(
                    insn.offset,
                    insn.mnemonic,
                    "UNKNOWN_OPCODE",
                    format!("Unrecognized Dalvik opcode 0x{:04X}", insn.opcode),
                ));
            }
        }
    }
    if covered_words != code.insns_count {
        issues.push(issue(
            covered_words,
            "<code_item>",
            "TRUNCATED_INSN",
            format!(
                "Decoded {covered_words} code units but header declares {} units",
                code.insns_count
            ),
        ));
    }

    // Structural per-instruction checks (register bounds, pool bounds, branch/switch targets).
    for insn in &insns {
        if insn.group == OpcodeGroup::Payload {
            continue;
        }
        verify_insn_regs_and_pools(dex, insn, code.registers_size, &exec_offsets, &payload_offsets, &mut issues);
    }

    // Structural try/catch bounds.
    for tb in &tries {
        if tb.start_pc >= tb.end_pc || tb.end_pc > code.insns_count {
            issues.push(issue(
                tb.start_pc,
                "<try>",
                "BAD_TRY_RANGE",
                format!(
                    "Try block [0x{:x}, 0x{:x}) out of bounds for {} code units",
                    tb.start_pc, tb.end_pc, code.insns_count
                ),
            ));
        }
        for h in &tb.handlers {
            if !exec_offsets.contains(&h.handler_pc) {
                issues.push(issue(
                    tb.start_pc,
                    "<catch>",
                    "BAD_CATCH_TARGET",
                    format!(
                        "Catch handler target pc=0x{:x} does not land on an executable instruction boundary",
                        h.handler_pc
                    ),
                ));
            }
        }
    }

    // Check fallthrough off last executable instruction.
    if let Some(last_exec) = insns.iter().rev().find(|i| i.group != OpcodeGroup::Payload) {
        if !matches!(
            last_exec.group,
            OpcodeGroup::Return | OpcodeGroup::Throw | OpcodeGroup::Goto
        ) {
            issues.push(issue(
                last_exec.offset,
                last_exec.mnemonic,
                "FALLTHROUGH_END",
                "Control flow can fall off the end of method without return, throw, or goto",
            ));
        }
    }

    // Forward RegType abstract interpretation over CFG when structural prerequisites passed.
    if issues.is_empty() && !insns.is_empty() {
        run_regtype_dataflow(dex, method, &code, code_bytes, &insns, &tries, &mut issues);
    }

    MethodVerificationReport {
        passed: issues.iter().all(|i| i.severity != "error"),
        class_descriptor,
        method_idx: method.method_idx,
        method_name,
        registers_size: code.registers_size,
        ins_size: code.ins_size,
        instruction_count: insns.iter().filter(|i| i.group != OpcodeGroup::Payload).count(),
        issues,
    }
}

fn verify_insn_regs_and_pools(
    dex: &DexFile,
    insn: &DalvikInstruction,
    registers_size: u16,
    exec_offsets: &HashSet<u32>,
    payload_offsets: &HashSet<u32>,
    issues: &mut Vec<MethodVerificationIssue>,
) {
    let op_byte = (insn.opcode & 0xFF) as u8;
    for (idx, &reg) in insn.registers.iter().enumerate() {
        if reg >= registers_size {
            issues.push(issue(
                insn.offset,
                insn.mnemonic,
                "REG_OUT_OF_RANGE",
                format!("Register v{reg} >= registers_size ({registers_size})"),
            ));
        } else if reg_slot_is_wide(insn, op_byte, idx) && reg + 1 >= registers_size {
            issues.push(issue(
                insn.offset,
                insn.mnemonic,
                "WIDE_REG_OVERFLOW",
                format!("Wide register pair v{reg}/v{} exceeds registers_size ({registers_size})", reg + 1),
            ));
        }
    }

    if let Some(pool_idx) = insn.index {
        let entry = get_opcode_entry(op_byte);
        let limit = match entry.ref_kind {
            RefKind::String => Some(("string_idx", dex.header.string_ids_size)),
            RefKind::Type => Some(("type_idx", dex.header.type_ids_size)),
            RefKind::Field => Some(("field_idx", dex.header.field_ids_size)),
            RefKind::Method => Some(("method_idx", dex.header.method_ids_size)),
            RefKind::MethodProto => Some(("proto_idx", dex.header.proto_ids_size)),
            _ => None,
        };
        if let Some((kind_name, max_sz)) = limit {
            if pool_idx >= max_sz {
                issues.push(issue(
                    insn.offset,
                    insn.mnemonic,
                    "POOL_OUT_OF_RANGE",
                    format!("{kind_name} {pool_idx} >= pool size ({max_sz})"),
                ));
            }
        }
    }

    match insn.group {
        OpcodeGroup::Goto | OpcodeGroup::IfTest | OpcodeGroup::IfTestZ => {
            if let Some(rel) = insn.target_offset {
                let target = insn.offset as i32 + rel;
                if target < 0 || !exec_offsets.contains(&(target as u32)) {
                    issues.push(issue(
                        insn.offset,
                        insn.mnemonic,
                        "BAD_BRANCH_TARGET",
                        format!("Branch target pc={target} is not a valid instruction boundary"),
                    ));
                }
            }
        }
        OpcodeGroup::PackedSwitch | OpcodeGroup::SparseSwitch => {
            let Some(rel) = insn.target_offset else {
                issues.push(issue(insn.offset, insn.mnemonic, "MISSING_PAYLOAD", "Switch missing payload offset"));
                return;
            };
            let payload_pc = insn.offset as i32 + rel;
            if payload_pc < 0 || !payload_offsets.contains(&(payload_pc as u32)) {
                issues.push(issue(
                    insn.offset,
                    insn.mnemonic,
                    "BAD_SWITCH_PAYLOAD",
                    format!("Switch payload offset {payload_pc} is invalid"),
                ));
                return;
            }
            match &insn.payload {
                Some(DalvikPayload::PackedSwitch { targets, .. })
                | Some(DalvikPayload::SparseSwitch { targets, .. }) => {
                    for &t in targets {
                        if t < 0 || !exec_offsets.contains(&(t as u32)) {
                            issues.push(issue(
                                insn.offset,
                                insn.mnemonic,
                                "BAD_SWITCH_TARGET",
                                format!("Switch case target pc={t} is not a valid instruction boundary"),
                            ));
                        }
                    }
                }
                _ => {
                    issues.push(issue(
                        insn.offset,
                        insn.mnemonic,
                        "MISMATCHED_SWITCH_PAYLOAD",
                        "Switch instruction does not point to a valid switch table payload",
                    ));
                }
            }
        }
        OpcodeGroup::FillArrayData => {
            let Some(rel) = insn.target_offset else {
                issues.push(issue(insn.offset, insn.mnemonic, "MISSING_PAYLOAD", "fill-array-data missing payload"));
                return;
            };
            let payload_pc = insn.offset as i32 + rel;
            if payload_pc < 0
                || !payload_offsets.contains(&(payload_pc as u32))
                || !matches!(insn.payload, Some(DalvikPayload::FillArrayData { .. }))
            {
                issues.push(issue(
                    insn.offset,
                    insn.mnemonic,
                    "BAD_ARRAY_PAYLOAD",
                    format!("fill-array-data payload offset {payload_pc} is invalid"),
                ));
            }
        }
        _ => {}
    }
}

fn reg_slot_is_wide(insn: &DalvikInstruction, op: u8, idx: usize) -> bool {
    match op {
        0x04..=0x06 // move-wide*
        | 0x16..=0x19 // const-wide*
        | 0x45 | 0x4C | 0x53 | 0x5A | 0x61 | 0x68 => idx == 0, // *-wide on reg0
        0x10 => idx == 0, // return-wide
        0x2D | 0x2F | 0x30 | 0x31 => idx == 1 || idx == 2, // cmpl-double, cmpg-double, cmp-long (dst=0, src1=1, src2=2)
        0x7D | 0x7E | 0x80 => true, // neg-long, not-long, neg-double
        0x81 | 0x83 | 0x87 | 0x89 => idx == 0, // (int|float)-to-(long|double): dst wide, src 32
        0x84 | 0x85 | 0x8A | 0x8C => idx == 1, // (long|double)-to-(int|float): dst 32, src wide
        0x86 | 0x8B => true, // long-to-double, double-to-long
        0x9B..=0xA5 | 0xAB..=0xAF | 0xBB..=0xC5 | 0xCB..=0xCF => true, // long/double binary ops
        _ => {
            let _ = insn;
            false
        }
    }
}

fn run_regtype_dataflow(
    dex: &DexFile,
    method: &DexMethodMeta<'_>,
    code: &crate::parser::DexCodeMeta,
    code_bytes: &[u8],
    insns: &[DalvikInstruction],
    tries: &[crate::instruction::TryCatchBlock],
    issues: &mut Vec<MethodVerificationIssue>,
) {
    let cfg = MethodCfg::build_with_bytes_and_tries(insns, code_bytes, tries);
    if cfg.blocks.is_empty() {
        return;
    }

    let n_regs = code.registers_size as usize;
    let mut entry_state = vec![RegType::Undefined; n_regs];

    // Seed incoming parameter registers at v[registers_size - ins_size .. registers_size].
    let param_base = n_regs.saturating_sub(code.ins_size as usize);
    let mut p_reg = param_base;
    if (method.access_flags & ACC_STATIC) == 0 && p_reg < n_regs {
        entry_state[p_reg] = if method.name == "<init>" {
            RegType::UninitializedThis
        } else {
            RegType::Reference
        };
        p_reg += 1;
    }
    for p_desc in &method.param_types {
        if matches!(p_desc.as_ref(), "J" | "D") {
            if p_reg + 1 < n_regs {
                entry_state[p_reg] = RegType::WideLo;
                entry_state[p_reg + 1] = RegType::WideHi;
            }
            p_reg += 2;
        } else {
            if p_reg < n_regs {
                entry_state[p_reg] = if p_desc.starts_with('L') || p_desc.starts_with('[') {
                    RegType::Reference
                } else {
                    RegType::Primitive32
                };
            }
            p_reg += 1;
        }
    }

    if p_reg > n_regs {
        issues.push(issue(
            0,
            "<proto>",
            "INS_SIZE_MISMATCH",
            format!(
                "Parameter register footprint ({}) exceeds registers_size ({})",
                p_reg - param_base,
                code.ins_size
            ),
        ));
        return;
    }

    let mut block_in: Vec<Option<Vec<RegType>>> = vec![None; cfg.blocks.len()];
    block_in[0] = Some(entry_state);

    let mut outgoing: Vec<Vec<usize>> = vec![Vec::new(); cfg.blocks.len()];
    for edge in &cfg.edges {
        outgoing[edge.from_block].push(edge.to_block);
    }

    let mut worklist = VecDeque::new();
    let mut in_queue = vec![false; cfg.blocks.len()];
    worklist.push_back(0usize);
    in_queue[0] = true;

    let mut reported_keys: HashSet<(u32, &'static str)> = HashSet::new();

    while let Some(b_idx) = worklist.pop_front() {
        in_queue[b_idx] = false;
        let Some(mut state) = block_in[b_idx].clone() else {
            continue;
        };

        for &insn_idx in &cfg.blocks[b_idx].instruction_indices {
            let insn = &insns[insn_idx];
            step_instruction(
                dex,
                method.return_type.as_ref(),
                insn,
                &mut state,
                issues,
                &mut reported_keys,
            );
        }

        for &succ in &outgoing[b_idx] {
            let changed = match &mut block_in[succ] {
                None => {
                    block_in[succ] = Some(state.clone());
                    true
                }
                Some(existing) => {
                    let mut diff = false;
                    for r in 0..n_regs {
                        let joined = RegType::join(&existing[r], &state[r]);
                        if joined != existing[r] {
                            existing[r] = joined;
                            diff = true;
                        }
                    }
                    diff
                }
            };
            if changed && !in_queue[succ] {
                worklist.push_back(succ);
                in_queue[succ] = true;
            }
        }
    }
}

fn step_instruction(
    dex: &DexFile,
    return_type: &str,
    insn: &DalvikInstruction,
    state: &mut [RegType],
    issues: &mut Vec<MethodVerificationIssue>,
    reported: &mut HashSet<(u32, &'static str)>,
) {
    let op = (insn.opcode & 0xFF) as u8;
    let mut flag_err = |code: &'static str, msg: String| {
        if reported.insert((insn.offset, code)) {
            issues.push(issue(insn.offset, insn.mnemonic, code, msg));
        }
    };

    let require_prim32 = |reg: u16, s: &[RegType], cb: &mut dyn FnMut(&'static str, String)| {
        let Some(ty) = s.get(reg as usize) else { return };
        if !ty.is_prim32() {
            cb(
                "TYPE_MISMATCH_PRIM32",
                format!("Expected 32-bit primitive in v{reg}, found {ty:?}"),
            );
        }
    };

    let require_ref = |reg: u16, s: &[RegType], cb: &mut dyn FnMut(&'static str, String)| {
        let Some(ty) = s.get(reg as usize) else { return };
        if !ty.is_ref_or_null() {
            cb(
                "TYPE_MISMATCH_REF",
                format!("Expected initialized reference/null in v{reg}, found {ty:?}"),
            );
        }
    };

    let require_wide = |reg: u16, s: &[RegType], cb: &mut dyn FnMut(&'static str, String)| {
        let r = reg as usize;
        if r + 1 >= s.len() || !RegType::is_wide_pair(&s[r], &s[r + 1]) {
            let lo = s.get(r);
            let hi = s.get(r + 1);
            cb(
                "CORRUPT_WIDE_PAIR",
                format!("Expected 64-bit wide pair at v{reg}/v{}, found ({lo:?}, {hi:?})", reg + 1),
            );
        }
    };

    match op {
        0x00 | 0x0E | 0x28..=0x2A => {} // nop, return-void, goto*
        0x0F => {
            // return vAA
            if let Some(&r0) = insn.registers.first() {
                if return_type == "V"
                    || matches!(return_type, "J" | "D")
                    || return_type.starts_with('L')
                    || return_type.starts_with('[')
                {
                    flag_err(
                        "RETURN_TYPE_MISMATCH",
                        format!("`return` incompatible with method return type `{return_type}`"),
                    );
                } else {
                    require_prim32(r0, state, &mut flag_err);
                }
            }
        }
        0x10 => {
            // return-wide vAA
            if let Some(&r0) = insn.registers.first() {
                if !matches!(return_type, "J" | "D") {
                    flag_err(
                        "RETURN_TYPE_MISMATCH",
                        format!("`return-wide` used in method returning `{return_type}`"),
                    );
                } else {
                    require_wide(r0, state, &mut flag_err);
                }
            }
        }
        0x11 => {
            // return-object vAA
            if let Some(&r0) = insn.registers.first() {
                if !return_type.starts_with('L') && !return_type.starts_with('[') {
                    flag_err(
                        "RETURN_TYPE_MISMATCH",
                        format!("`return-object` used in method returning `{return_type}`"),
                    );
                } else {
                    require_ref(r0, state, &mut flag_err);
                }
            }
        }
        0x01..=0x03 => {
            if let (Some(&dst), Some(&src)) = (insn.registers.first(), insn.registers.get(1)) {
                let src_ty = state.get(src as usize).cloned().unwrap_or(RegType::Undefined);
                if !src_ty.is_prim32() {
                    flag_err(
                        "MOVE_UNINIT",
                        format!("move source v{src} expected 32-bit primitive, found {src_ty:?}"),
                    );
                }
                write_single(state, dst, src_ty);
            }
        }
        0x04..=0x06 => {
            if let (Some(&dst), Some(&src)) = (insn.registers.first(), insn.registers.get(1)) {
                require_wide(src, state, &mut flag_err);
                write_wide(state, dst);
            }
        }
        0x07..=0x09 => {
            if let (Some(&dst), Some(&src)) = (insn.registers.first(), insn.registers.get(1)) {
                let src_ty = state.get(src as usize).cloned().unwrap_or(RegType::Undefined);
                if !src_ty.is_any_ref() {
                    flag_err(
                        "MOVE_OBJECT_TYPE_MISMATCH",
                        format!("move-object source v{src} expected reference, found {src_ty:?}"),
                    );
                }
                write_single(state, dst, src_ty);
            }
        }
        0x0A..=0x0C => {
            if let Some(&dst) = insn.registers.first() {
                if op == 0x0B {
                    write_wide(state, dst);
                } else if op == 0x0C {
                    write_single(state, dst, RegType::Reference);
                } else {
                    write_single(state, dst, RegType::Primitive32);
                }
            }
        }
        0x0D => {
            // move-exception
            if let Some(&dst) = insn.registers.first() {
                write_single(state, dst, RegType::Reference);
            }
        }
        0x12..=0x15 => {
            if let Some(&dst) = insn.registers.first() {
                let ty = if insn.literal == Some(0) {
                    RegType::ZeroOrNull
                } else {
                    RegType::Primitive32
                };
                write_single(state, dst, ty);
            }
        }
        0x16..=0x19 => {
            if let Some(&dst) = insn.registers.first() {
                write_wide(state, dst);
            }
        }
        0x1A..=0x1C | 0xFE..=0xFF => {
            if let Some(&dst) = insn.registers.first() {
                write_single(state, dst, RegType::Reference);
            }
        }
        0x1D | 0x1E | 0x27 => {
            // monitor-enter/exit, throw
            if let Some(&r0) = insn.registers.first() {
                require_ref(r0, state, &mut flag_err);
            }
        }
        0x1F => {
            // check-cast vAA, type
            if let Some(&r0) = insn.registers.first() {
                require_ref(r0, state, &mut flag_err);
                write_single(state, r0, RegType::Reference);
            }
        }
        0x20 => {
            // instance-of vA, vB, type
            if let (Some(&dst), Some(&obj)) = (insn.registers.first(), insn.registers.get(1)) {
                require_ref(obj, state, &mut flag_err);
                write_single(state, dst, RegType::Primitive32);
            }
        }
        0x21 => {
            // array-length vA, vB
            if let (Some(&dst), Some(&arr)) = (insn.registers.first(), insn.registers.get(1)) {
                require_ref(arr, state, &mut flag_err);
                write_single(state, dst, RegType::Primitive32);
            }
        }
        0x22 => {
            // new-instance vAA, type
            if let Some(&dst) = insn.registers.first() {
                write_single(state, dst, RegType::UninitializedNew(insn.offset));
            }
        }
        0x23 => {
            // new-array vA, vB, type
            if let (Some(&dst), Some(&len)) = (insn.registers.first(), insn.registers.get(1)) {
                require_prim32(len, state, &mut flag_err);
                write_single(state, dst, RegType::Reference);
            }
        }
        0x24 | 0x25 => {
            // filled-new-array* -> elements match scalar/ref, verified non-Undefined
            for &r in &insn.registers {
                if matches!(state.get(r as usize), None | Some(RegType::Undefined) | Some(RegType::Conflict)) {
                    flag_err("UNINIT_ARG", format!("filled-new-array register v{r} is uninitialized or conflicted"));
                }
            }
        }
        0x26 => {
            // fill-array-data vAA
            if let Some(&r0) = insn.registers.first() {
                require_ref(r0, state, &mut flag_err);
            }
        }
        0x2B | 0x2C => {
            // packed-switch / sparse-switch vAA
            if let Some(&r0) = insn.registers.first() {
                require_prim32(r0, state, &mut flag_err);
            }
        }
        0x2D..=0x31 => {
            if let (Some(&dst), Some(&s1), Some(&s2)) =
                (insn.registers.first(), insn.registers.get(1), insn.registers.get(2))
            {
                if matches!(op, 0x2E) {
                    require_prim32(s1, state, &mut flag_err);
                    require_prim32(s2, state, &mut flag_err);
                } else {
                    require_wide(s1, state, &mut flag_err);
                    require_wide(s2, state, &mut flag_err);
                }
                write_single(state, dst, RegType::Primitive32);
            }
        }
        0x32..=0x37 => {
            // if-eq..if-le vA, vB
            if let (Some(&a), Some(&b)) = (insn.registers.first(), insn.registers.get(1)) {
                let ta = state.get(a as usize);
                let tb = state.get(b as usize);
                if matches!(ta, None | Some(RegType::Undefined) | Some(RegType::Conflict) | Some(RegType::WideLo) | Some(RegType::WideHi))
                    || matches!(tb, None | Some(RegType::Undefined) | Some(RegType::Conflict) | Some(RegType::WideLo) | Some(RegType::WideHi))
                {
                    flag_err("BRANCH_REG_INVALID", format!("Invalid comparison operands v{a}={ta:?}, v{b}={tb:?}"));
                }
            }
        }
        0x38..=0x3D => {
            // if-eqz..if-lez vAA
            if let Some(&a) = insn.registers.first() {
                let ta = state.get(a as usize);
                if matches!(ta, None | Some(RegType::Undefined) | Some(RegType::Conflict) | Some(RegType::WideLo) | Some(RegType::WideHi)) {
                    flag_err("BRANCH_REG_INVALID", format!("Invalid unary branch operand v{a}={ta:?}"));
                }
            }
        }
        0x44..=0x4A => {
            // aget* vA, vB, vC
            if let (Some(&dst), Some(&arr), Some(&idx)) =
                (insn.registers.first(), insn.registers.get(1), insn.registers.get(2))
            {
                require_ref(arr, state, &mut flag_err);
                require_prim32(idx, state, &mut flag_err);
                match op {
                    0x45 => write_wide(state, dst),
                    0x46 => write_single(state, dst, RegType::Reference),
                    _ => write_single(state, dst, RegType::Primitive32),
                }
            }
        }
        0x4B..=0x51 => {
            // aput* vA, vB, vC
            if let (Some(&val), Some(&arr), Some(&idx)) =
                (insn.registers.first(), insn.registers.get(1), insn.registers.get(2))
            {
                require_ref(arr, state, &mut flag_err);
                require_prim32(idx, state, &mut flag_err);
                match op {
                    0x4C => require_wide(val, state, &mut flag_err),
                    0x4D => require_ref(val, state, &mut flag_err),
                    _ => require_prim32(val, state, &mut flag_err),
                }
            }
        }
        0x52..=0x58 => {
            // iget* vA, vB, field
            if let (Some(&dst), Some(&obj)) = (insn.registers.first(), insn.registers.get(1)) {
                require_ref(obj, state, &mut flag_err);
                match op {
                    0x53 => write_wide(state, dst),
                    0x54 => write_single(state, dst, RegType::Reference),
                    _ => write_single(state, dst, RegType::Primitive32),
                }
            }
        }
        0x59..=0x5F => {
            // iput* vA, vB, field
            if let (Some(&val), Some(&obj)) = (insn.registers.first(), insn.registers.get(1)) {
                require_ref(obj, state, &mut flag_err);
                match op {
                    0x5A => require_wide(val, state, &mut flag_err),
                    0x5B => require_ref(val, state, &mut flag_err),
                    _ => require_prim32(val, state, &mut flag_err),
                }
            }
        }
        0x60..=0x66 => {
            // sget* vAA, field
            if let Some(&dst) = insn.registers.first() {
                match op {
                    0x61 => write_wide(state, dst),
                    0x62 => write_single(state, dst, RegType::Reference),
                    _ => write_single(state, dst, RegType::Primitive32),
                }
            }
        }
        0x67..=0x6D => {
            // sput* vAA, field
            if let Some(&val) = insn.registers.first() {
                match op {
                    0x68 => require_wide(val, state, &mut flag_err),
                    0x69 => require_ref(val, state, &mut flag_err),
                    _ => require_prim32(val, state, &mut flag_err),
                }
            }
        }
        0x6E..=0x72 | 0x74..=0x78 => {
            verify_invoke(dex, insn, op, state, &mut flag_err);
        }
        0xFA..=0xFD => {
            for &r in &insn.registers {
                if matches!(state.get(r as usize), None | Some(RegType::Undefined) | Some(RegType::Conflict)) {
                    flag_err("UNINIT_ARG", format!("Invoke register v{r} is uninitialized or conflicted"));
                }
            }
        }
        0x7B..=0x8F => {
            if let (Some(&dst), Some(&src)) = (insn.registers.first(), insn.registers.get(1)) {
                let src_wide = matches!(op, 0x7D | 0x7E | 0x80 | 0x84..=0x86 | 0x8A..=0x8C);
                let dst_wide = matches!(op, 0x7D | 0x7E | 0x80 | 0x81 | 0x83 | 0x86 | 0x87 | 0x89 | 0x8B);
                if src_wide {
                    require_wide(src, state, &mut flag_err);
                } else {
                    require_prim32(src, state, &mut flag_err);
                }
                if dst_wide {
                    write_wide(state, dst);
                } else {
                    write_single(state, dst, RegType::Primitive32);
                }
            }
        }
        0x90..=0xE2 => {
            let is_2addr_or_lit = matches!(op, 0xB0..=0xE2);
            let is_lit = matches!(op, 0xD0..=0xE2);
            let is_wide = !is_lit
                && matches!(
                    op,
                    0x9B..=0xA5 | 0xAB..=0xAF | 0xBB..=0xC5 | 0xCB..=0xCF
                );
            if is_lit {
                if let (Some(&dst), Some(&src)) = (insn.registers.first(), insn.registers.get(1)) {
                    require_prim32(src, state, &mut flag_err);
                    write_single(state, dst, RegType::Primitive32);
                }
            } else if is_2addr_or_lit {
                if let (Some(&dst), Some(&src)) = (insn.registers.first(), insn.registers.get(1)) {
                    if is_wide {
                        require_wide(dst, state, &mut flag_err);
                        require_wide(src, state, &mut flag_err);
                        write_wide(state, dst);
                    } else {
                        require_prim32(dst, state, &mut flag_err);
                        require_prim32(src, state, &mut flag_err);
                        write_single(state, dst, RegType::Primitive32);
                    }
                }
            } else if let (Some(&dst), Some(&s1), Some(&s2)) =
                (insn.registers.first(), insn.registers.get(1), insn.registers.get(2))
            {
                if is_wide {
                    require_wide(s1, state, &mut flag_err);
                    require_wide(s2, state, &mut flag_err);
                    write_wide(state, dst);
                } else {
                    require_prim32(s1, state, &mut flag_err);
                    require_prim32(s2, state, &mut flag_err);
                    write_single(state, dst, RegType::Primitive32);
                }
            }
        }
        _ => {}
    }
    let _ = Format::F00x;
}

fn verify_invoke(
    dex: &DexFile,
    insn: &DalvikInstruction,
    op: u8,
    state: &mut [RegType],
    flag_err: &mut dyn FnMut(&'static str, String),
) {
    let Some(m_idx) = insn.index else { return };
    let is_static = matches!(op, 0x71 | 0x77);
    let m_name = dex.get_method_name(m_idx);
    let Some((_, _, params)) = dex.get_method_proto(m_idx) else { return };

    let mut pos = 0usize;
    if !is_static {
        let Some(&this_reg) = insn.registers.get(pos) else {
            flag_err("ARG_COUNT_MISMATCH", "Missing receiver register on instance invoke".to_string());
            return;
        };
        let this_ty = state.get(this_reg as usize).cloned().unwrap_or(RegType::Undefined);
        let is_ctor_call = m_name.as_deref() == Some("<init>");
        if is_ctor_call {
            if !this_ty.is_any_ref() {
                flag_err(
                    "CTOR_RECEIVER_INVALID",
                    format!("Constructor `<init>` receiver v{this_reg} is {this_ty:?}"),
                );
            } else if matches!(this_ty, RegType::UninitializedThis | RegType::UninitializedNew(_)) {
                // Promote all aliases of this uninitialized object to initialized `Reference`.
                for slot in state.iter_mut() {
                    if *slot == this_ty {
                        *slot = RegType::Reference;
                    }
                }
            }
        } else if !this_ty.is_ref_or_null() {
            flag_err(
                "RECEIVER_UNINIT",
                format!("Method invoke receiver v{this_reg} expected initialized reference, found {this_ty:?}"),
            );
        }
        pos += 1;
    }

    for p_desc in params {
        if matches!(p_desc.as_ref(), "J" | "D") {
            let (Some(&lo), Some(&hi)) = (insn.registers.get(pos), insn.registers.get(pos + 1)) else {
                flag_err("ARG_COUNT_MISMATCH", "Invoke missing register pair for 64-bit parameter".to_string());
                return;
            };
            if hi != lo + 1 {
                flag_err("WIDE_PAIR_NONCONTIGUOUS", format!("Invoke wide parameter uses non-contiguous registers v{lo}, v{hi}"));
            } else {
                let t_lo = state.get(lo as usize);
                let t_hi = state.get(hi as usize);
                if t_lo != Some(&RegType::WideLo) || t_hi != Some(&RegType::WideHi) {
                    flag_err("ARG_TYPE_MISMATCH", format!("Invoke expected wide pair at v{lo}/v{hi}, found ({t_lo:?}, {t_hi:?})"));
                }
            }
            pos += 2;
        } else {
            let Some(&r) = insn.registers.get(pos) else {
                flag_err("ARG_COUNT_MISMATCH", "Invoke has fewer argument registers than method signature requires".to_string());
                return;
            };
            let t = state.get(r as usize);
            if p_desc.starts_with('L') || p_desc.starts_with('[') {
                if !t.map_or(false, RegType::is_ref_or_null) {
                    flag_err("ARG_TYPE_MISMATCH", format!("Invoke expected reference `{p_desc}` in v{r}, found {t:?}"));
                }
            } else if !t.map_or(false, RegType::is_prim32) {
                flag_err("ARG_TYPE_MISMATCH", format!("Invoke expected primitive `{p_desc}` in v{r}, found {t:?}"));
            }
            pos += 1;
        }
    }
}

fn write_single(state: &mut [RegType], reg: u16, ty: RegType) {
    let r = reg as usize;
    if r >= state.len() {
        return;
    }
    if state[r] == RegType::WideHi && r > 0 {
        state[r - 1] = RegType::Conflict;
    } else if state[r] == RegType::WideLo && r + 1 < state.len() {
        state[r + 1] = RegType::Conflict;
    }
    state[r] = ty;
}

fn write_wide(state: &mut [RegType], reg: u16) {
    let r = reg as usize;
    if r + 1 >= state.len() {
        return;
    }
    if state[r] == RegType::WideHi && r > 0 {
        state[r - 1] = RegType::Conflict;
    }
    if state[r + 1] == RegType::WideLo && r + 2 < state.len() {
        state[r + 2] = RegType::Conflict;
    }
    state[r] = RegType::WideLo;
    state[r + 1] = RegType::WideHi;
}

fn issue(
    pc_word: u32,
    mnemonic: &str,
    code: &'static str,
    message: impl Into<String>,
) -> MethodVerificationIssue {
    MethodVerificationIssue {
        pc_word,
        mnemonic: mnemonic.to_string(),
        severity: "error",
        code,
        message: message.into(),
    }
}

pub fn verify_dex_method_json(dex: &DexFile, class_def_idx: u32, method_idx: u32) -> Option<String> {
    let report = verify_dex_method(dex, class_def_idx, method_idx)?;
    serde_json::to_string(&report).ok()
}

pub fn verify_dex_class_json(dex: &DexFile, class_def_idx: u32) -> Option<String> {
    let reports = verify_dex_class(dex, class_def_idx)?;
    serde_json::to_string(&reports).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dex_parser::{BuiltClass, BuiltCode, BuiltMethod, BuiltTry, DexBuilder};

    fn build_single_method_dex(
        proto: &str,
        registers_size: u16,
        ins_size: u16,
        insns: Vec<u8>,
        tries: Vec<BuiltTry>,
    ) -> DexFile {
        let mut b = DexBuilder::new();
        b.add_class(BuiltClass {
            descriptor: "Lcom/example/VerifyTest;".into(),
            access_flags: 1,
            superclass: Some("Ljava/lang/Object;".into()),
            interfaces: vec![],
            source_file: None,
            static_fields: vec![],
            instance_fields: vec![],
            direct_methods: vec![BuiltMethod {
                class: "Lcom/example/VerifyTest;".into(),
                name: "test".into(),
                proto: proto.into(),
                access_flags: 9, // public static
                direct: true,
                code: Some(BuiltCode {
                    registers_size,
                    ins_size,
                    outs_size: 0,
                    insns,
                    tries,
                    debug_info_off: 0,
                    debug_ops: vec![],
                }),
            }],
            virtual_methods: vec![],
            annotations: Default::default(),
        });
        let raw = b.finish().expect("valid DEX");
        DexFile::parse(&raw).expect("parse DEX")
    }

    #[test]
    fn test_verifier_passes_valid_branch_and_try_catch() {
        let dex = build_single_method_dex(
            "(I)I",
            2,
            1,
            vec![
                0x38, 0x01, 0x03, 0x00, // if-eqz v1, +3 (word 3)
                0x0f, 0x01,             // return v1
                0x12, 0x50,             // const/4 v0, #5
                0x0f, 0x00,             // return v0
            ],
            vec![BuiltTry {
                start_unit: 0,
                insn_count: 3,
                handlers: vec![],
                catch_all: Some(3),
            }],
        );
        let cls = dex.get_class_def_full(0).unwrap();
        let report = verify_dex_method(&dex, 0, cls.direct_methods[0].method_idx).unwrap();
        assert!(report.passed, "expected pass, got {:?}", report.issues);
    }

    #[test]
    fn test_verifier_catches_out_of_range_register_and_mid_insn_branch() {
        // const/4 v5, #1 inside registers_size=2 + if-eqz landing at word 1 (mid 2-word insn)
        let dex = build_single_method_dex(
            "(I)I",
            2,
            1,
            vec![
                0x38, 0x01, 0x01, 0x00, // if-eqz v1, +1 -> word 1 (mid instruction!)
                0x12, 0x15,             // const/4 v5, #1 (v5 out of range!)
                0x0f, 0x05,             // return v5
            ],
            vec![],
        );
        let cls = dex.get_class_def_full(0).unwrap();
        let report = verify_dex_method(&dex, 0, cls.direct_methods[0].method_idx).unwrap();
        assert!(!report.passed);
        assert!(report.issues.iter().any(|i| i.code == "BAD_BRANCH_TARGET"));
        assert!(report.issues.iter().any(|i| i.code == "REG_OUT_OF_RANGE"));
    }

    #[test]
    fn test_verifier_catches_prim_returned_as_object_and_wide_overflow() {
        let dex = build_single_method_dex(
            "(I)Ljava/lang/String;",
            2,
            1,
            vec![
                0x12, 0x30, // const/4 v0, #3 (int)
                0x11, 0x00, // return-object v0 -> type mismatch!
            ],
            vec![],
        );
        let cls = dex.get_class_def_full(0).unwrap();
        let r1 = verify_dex_method(&dex, 0, cls.direct_methods[0].method_idx).unwrap();
        assert!(!r1.passed);
        assert!(r1.issues.iter().any(|i| i.code == "TYPE_MISMATCH_REF"));

        let dex2 = build_single_method_dex(
            "(J)J",
            2,
            2,
            vec![
                0x16, 0x01, 0x01, 0x00, // const-wide/16 v1, #1 -> v1/v2 overflows registers_size=2!
                0x10, 0x00,             // return-wide v0
            ],
            vec![],
        );
        let cls2 = dex2.get_class_def_full(0).unwrap();
        let r2 = verify_dex_method(&dex2, 0, cls2.direct_methods[0].method_idx).unwrap();
        assert!(!r2.passed);
        assert!(r2.issues.iter().any(|i| i.code == "WIDE_REG_OVERFLOW"));
    }
}
