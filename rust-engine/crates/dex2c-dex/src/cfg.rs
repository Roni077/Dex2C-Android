//! Control Flow Graph (CFG) construction powered by `androguard/dex-bytecode`.
//! Supports branch targets, switch payload case expansion (`packed-switch` / `sparse-switch`),
//! return/throw block termination, and `try/catch` exception handler edges.

use crate::instruction::{DalvikInstruction, DalvikPayload, OpcodeGroup, TryCatchBlock};
use dex_bytecode::{basic_blocks, decode_all, exception_edges, TryCatchEntry};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    Fallthrough,
    Branch,
    SwitchCase,
    Catch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockTerminatorKind {
    Entry,
    Fallthrough,
    ConditionalBranch,
    UnconditionalJump,
    Switch,
    Return,
    Throw,
    ExceptionHandler,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from_block: usize,
    pub to_block: usize,
    pub to_offset: u32, // target 16-bit code unit offset
    pub kind: EdgeKind,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: usize,
    pub start_offset: u32,     // inclusive start 16-bit word offset
    pub end_offset: u32,       // last instruction word offset (back-compat)
    pub end_offset_words: u32, // exclusive end word offset (start + width of last)
    pub instruction_indices: Vec<usize>,
    pub terminator_kind: BlockTerminatorKind,
    pub is_entry: bool,
    pub is_exception_handler: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MethodCfg {
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<CfgEdge>,
    pub branch_count: usize,
    pub exception_edge_count: usize,
    pub engine_label: String,
}

impl MethodCfg {
    /// Builds CFG from pre-decoded `DalvikInstruction` slice without try/catch edges.
    pub fn build(instructions: &[DalvikInstruction]) -> Self {
        let mut bytes = Vec::new();
        for insn in instructions {
            let off = insn.offset as usize * 2;
            while bytes.len() < off {
                bytes.push(0);
            }
            for w in &insn.raw_words {
                bytes.extend_from_slice(&w.to_le_bytes());
            }
            while bytes.len() < (insn.offset as usize + insn.length_units as usize) * 2 {
                bytes.push(0);
            }
        }
        Self::build_with_bytes_and_tries(instructions, &bytes, &[])
    }

    /// Builds CFG using `dex_bytecode::{decode_all, basic_blocks, exception_edges}` plus switch & try/catch blocks.
    pub fn build_with_bytes_and_tries(
        instructions: &[DalvikInstruction],
        code_bytes: &[u8],
        tries: &[TryCatchBlock],
    ) -> Self {
        let exec_indices: Vec<usize> = instructions
            .iter()
            .enumerate()
            .filter(|(_, ins)| ins.group != OpcodeGroup::Payload)
            .map(|(idx, _)| idx)
            .collect();

        if exec_indices.is_empty() {
            return Self {
                blocks: Vec::new(),
                edges: Vec::new(),
                branch_count: 0,
                exception_edge_count: 0,
                engine_label: "Rust dex-bytecode CFG".to_string(),
            };
        }

        let exec_offsets: HashSet<u32> = exec_indices
            .iter()
            .map(|&idx| instructions[idx].offset)
            .collect();

        let mut leaders = BTreeSet::new();
        let entry_word = instructions[exec_indices[0]].offset;
        leaders.insert(entry_word);

        // Seed block boundaries from dex_bytecode::basic_blocks (covers explicit branches & switch targets)
        let raw_decoded = decode_all(code_bytes, 0).unwrap_or_default();
        let bytecode_blocks = basic_blocks(&raw_decoded, code_bytes, 0);
        for b in &bytecode_blocks {
            let start_word = b.start_offset / 2;
            if exec_offsets.contains(&start_word) {
                leaders.insert(start_word);
            }
            for &succ in &b.successors {
                let sw = succ / 2;
                if exec_offsets.contains(&sw) {
                    leaders.insert(sw);
                }
            }
            if let Some(ft) = b.fallthrough_to {
                let fw = ft / 2;
                if exec_offsets.contains(&fw) {
                    leaders.insert(fw);
                }
            }
        }

        // Split after Return / Throw instructions & at decoded targets as well
        for (pos, &idx) in exec_indices.iter().enumerate() {
            let insn = &instructions[idx];
            let next_word = exec_indices.get(pos + 1).map(|&ni| instructions[ni].offset);
            match insn.group {
                OpcodeGroup::Goto | OpcodeGroup::IfTest | OpcodeGroup::IfTestZ => {
                    if let Some(rel) = insn.target_offset {
                        let tgt = insn.offset as i32 + rel;
                        if tgt >= 0 && exec_offsets.contains(&(tgt as u32)) {
                            leaders.insert(tgt as u32);
                        }
                    }
                    if let Some(nw) = next_word {
                        leaders.insert(nw);
                    }
                }
                OpcodeGroup::PackedSwitch | OpcodeGroup::SparseSwitch => {
                    match &insn.payload {
                        Some(DalvikPayload::PackedSwitch { targets, .. }) => {
                            for &t in targets {
                                if t >= 0 && exec_offsets.contains(&(t as u32)) {
                                    leaders.insert(t as u32);
                                }
                            }
                        }
                        Some(DalvikPayload::SparseSwitch { targets, .. }) => {
                            for &t in targets {
                                if t >= 0 && exec_offsets.contains(&(t as u32)) {
                                    leaders.insert(t as u32);
                                }
                            }
                        }
                        _ => {}
                    }
                    if let Some(nw) = next_word {
                        leaders.insert(nw);
                    }
                }
                OpcodeGroup::Return | OpcodeGroup::Throw => {
                    if let Some(nw) = next_word {
                        leaders.insert(nw);
                    }
                }
                _ => {}
            }
        }

        // Seed block boundaries & handler set from try/catch metadata
        let mut catch_handler_words = HashSet::new();
        for tb in tries {
            if exec_offsets.contains(&tb.start_pc) {
                leaders.insert(tb.start_pc);
            }
            if exec_offsets.contains(&tb.end_pc) {
                leaders.insert(tb.end_pc);
            }
            for h in &tb.handlers {
                if exec_offsets.contains(&h.handler_pc) {
                    leaders.insert(h.handler_pc);
                    catch_handler_words.insert(h.handler_pc);
                }
            }
        }

        // Partition executable instructions into contiguous BasicBlocks
        let sorted_leaders: Vec<u32> = leaders.into_iter().collect();
        let mut block_slices: Vec<(u32, Vec<usize>)> = Vec::with_capacity(sorted_leaders.len());
        let mut word_to_block_id: HashMap<u32, usize> = HashMap::new();

        for (i, &start_word) in sorted_leaders.iter().enumerate() {
            let next_leader = sorted_leaders.get(i + 1).copied();
            let slice: Vec<usize> = exec_indices
                .iter()
                .copied()
                .filter(|&idx| {
                    let off = instructions[idx].offset;
                    off >= start_word && next_leader.map_or(true, |nl| off < nl)
                })
                .collect();
            if !slice.is_empty() {
                let blk_id = block_slices.len();
                word_to_block_id.insert(start_word, blk_id);
                block_slices.push((start_word, slice));
            }
        }

        let mut edges: Vec<CfgEdge> = Vec::new();
        let mut edge_dedup: HashSet<(usize, usize, EdgeKind, String)> = HashSet::new();
        let mut branch_count = 0usize;
        let mut exception_edge_count = 0usize;

        let mut push_edge = |from_block: usize,
                             to_word: u32,
                             kind: EdgeKind,
                             label: String| {
            if let Some(&to_block) = word_to_block_id.get(&to_word) {
                if edge_dedup.insert((from_block, to_block, kind, label.clone())) {
                    if kind == EdgeKind::Catch {
                        exception_edge_count += 1;
                    }
                    edges.push(CfgEdge {
                        from_block,
                        to_block,
                        to_offset: to_word,
                        kind,
                        label,
                    });
                }
            }
        };

        let mut blocks = Vec::with_capacity(block_slices.len());

        // Construct TryCatchEntry slice (byte offsets) for dex_bytecode::exception_edges
        let mut try_entries = Vec::new();
        let mut try_handler_label_map: HashMap<(u32, u32), String> = HashMap::new();
        for tb in tries {
            for h in &tb.handlers {
                let type_label = h
                    .type_desc
                    .as_deref()
                    .map(descriptor_simple_name)
                    .unwrap_or("<all>");
                let label = format!("Catch {type_label}");
                try_handler_label_map
                    .entry((tb.start_pc * 2, h.handler_pc * 2))
                    .or_insert(label);
                try_entries.push(TryCatchEntry {
                    start_offset: tb.start_pc * 2,
                    end_offset: tb.end_pc * 2,
                    handler_offset: h.handler_pc * 2,
                    type_index: None,
                });
            }
        }

        let mut dex_blocks_for_exceptions = Vec::with_capacity(block_slices.len());

        for (blk_id, (start_word, indices)) in block_slices.iter().enumerate() {
            let last_insn = &instructions[*indices.last().unwrap()];
            let next_block_word = block_slices.get(blk_id + 1).map(|(w, _)| *w);
            let end_word = last_insn.offset;
            let end_words = end_word + last_insn.length_units as u32;

            dex_blocks_for_exceptions.push(dex_bytecode::BasicBlock {
                start_offset: start_word * 2,
                end_offset: end_words * 2,
                successors: Vec::new(),
                fallthrough_to: None,
            });

            let terminator = match last_insn.group {
                OpcodeGroup::Goto => {
                    branch_count += 1;
                    if let Some(rel) = last_insn.target_offset {
                        let tgt = last_insn.offset as i32 + rel;
                        if tgt >= 0 {
                            push_edge(blk_id, tgt as u32, EdgeKind::Branch, "Goto".into());
                        }
                    }
                    BlockTerminatorKind::UnconditionalJump
                }
                OpcodeGroup::IfTest | OpcodeGroup::IfTestZ => {
                    branch_count += 1;
                    if let Some(rel) = last_insn.target_offset {
                        let tgt = last_insn.offset as i32 + rel;
                        if tgt >= 0 {
                            push_edge(blk_id, tgt as u32, EdgeKind::Branch, "True".into());
                        }
                    }
                    if let Some(nw) = next_block_word {
                        push_edge(blk_id, nw, EdgeKind::Fallthrough, "Fallthrough".into());
                    }
                    BlockTerminatorKind::ConditionalBranch
                }
                OpcodeGroup::PackedSwitch | OpcodeGroup::SparseSwitch => {
                    branch_count += 1;
                    match &last_insn.payload {
                        Some(DalvikPayload::PackedSwitch {
                            first_key, targets, ..
                        }) => {
                            for (i, &tgt) in targets.iter().enumerate() {
                                if tgt >= 0 {
                                    push_edge(
                                        blk_id,
                                        tgt as u32,
                                        EdgeKind::SwitchCase,
                                        format!("case {}", first_key + i as i32),
                                    );
                                }
                            }
                        }
                        Some(DalvikPayload::SparseSwitch { keys, targets, .. }) => {
                            for (k, &tgt) in keys.iter().zip(targets.iter()) {
                                if tgt >= 0 {
                                    push_edge(
                                        blk_id,
                                        tgt as u32,
                                        EdgeKind::SwitchCase,
                                        format!("case {}", k),
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                    if let Some(nw) = next_block_word {
                        push_edge(blk_id, nw, EdgeKind::Fallthrough, "Default".into());
                    }
                    BlockTerminatorKind::Switch
                }
                OpcodeGroup::Return => BlockTerminatorKind::Return,
                OpcodeGroup::Throw => BlockTerminatorKind::Throw,
                _ => {
                    if let Some(nw) = next_block_word {
                        push_edge(blk_id, nw, EdgeKind::Fallthrough, "Fallthrough".into());
                    }
                    BlockTerminatorKind::Fallthrough
                }
            };

            blocks.push(BasicBlock {
                id: blk_id,
                start_offset: *start_word,
                end_offset: end_word,
                end_offset_words: end_words,
                instruction_indices: indices.clone(),
                terminator_kind: terminator,
                is_entry: blk_id == 0,
                is_exception_handler: catch_handler_words.contains(start_word),
            });
        }

        // Attach exception edges via dex_bytecode::exception_edges
        if !try_entries.is_empty() {
            let ex_edges = exception_edges(&try_entries, &dex_blocks_for_exceptions);
            for (from_byte, to_byte) in ex_edges {
                let from_word = from_byte / 2;
                let to_word = to_byte / 2;
                if let Some(&from_blk) = word_to_block_id.get(&from_word) {
                    let label = tries
                        .iter()
                        .filter(|tb| tb.end_pc > from_word && tb.start_pc < blocks[from_blk].end_offset_words)
                        .flat_map(|tb| tb.handlers.iter())
                        .find(|h| h.handler_pc == to_word)
                        .and_then(|h| h.type_desc.as_deref())
                        .map(|d| format!("Catch {}", descriptor_simple_name(d)))
                        .unwrap_or_else(|| "Catch <all>".to_string());
                    push_edge(from_blk, to_word, EdgeKind::Catch, label);
                }
            }
        }

        MethodCfg {
            blocks,
            edges,
            branch_count,
            exception_edge_count,
            engine_label: "Rust dex-bytecode CFG".to_string(),
        }
    }
}

fn descriptor_simple_name(desc: &str) -> &str {
    let trimmed = desc.strip_prefix('L').unwrap_or(desc);
    let trimmed = trimmed.strip_suffix(';').unwrap_or(trimmed);
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}
