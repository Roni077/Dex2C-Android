//! JSON serialization bridge exposing `dex2c-dex` (`dex-parser` + `dex-bytecode`)
//! Dalvik disassembly, payload linking, try/catch blocks, and CFG construction to JNI.

use crate::dex::DexFile;
use dex2c_dex::cfg::{BlockTerminatorKind, EdgeKind, MethodCfg};
use dex2c_dex::{DalvikDisassembler, DalvikInstruction, DalvikPayload, OpcodeGroup, TryCatchBlock};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MethodDisassemblyJson {
    instructions: Vec<InstructionJson>,
    try_blocks: Vec<TryBlockJson>,
    cfg: CfgJson,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstructionJson {
    offset_words: u32,
    width_words: u16,
    opcode: u16,
    mnemonic: &'static str,
    format: &'static str,
    operands_text: String,
    raw_words: Vec<u16>,
    category: &'static str,
    reg_a: Option<u16>,
    reg_b: Option<u16>,
    reg_c: Option<u16>,
    reg_list: Vec<u16>,
    is_range_invoke: bool,
    literal: Option<i64>,
    target_offset: Option<i32>,
    string_ref: Option<String>,
    type_ref: Option<String>,
    field_ref: Option<FieldRefJson>,
    method_ref: Option<MethodRefJson>,
    payload: Option<PayloadJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldRefJson {
    defining_class: String,
    #[serde(rename = "type")]
    field_type: String,
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProtoJson {
    shorty: String,
    return_type: String,
    parameter_types: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MethodRefJson {
    defining_class: String,
    proto: ProtoJson,
    name: String,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PayloadJson {
    PackedSwitch {
        #[serde(rename = "offsetWords")]
        offset_words: u32,
        #[serde(rename = "wordCount")]
        word_count: u16,
        #[serde(rename = "firstKey")]
        first_key: i32,
        #[serde(rename = "targetOffsets")]
        target_offsets: Vec<i32>,
    },
    SparseSwitch {
        #[serde(rename = "offsetWords")]
        offset_words: u32,
        #[serde(rename = "wordCount")]
        word_count: u16,
        keys: Vec<i32>,
        #[serde(rename = "targetOffsets")]
        target_offsets: Vec<i32>,
    },
    FillArrayData {
        #[serde(rename = "offsetWords")]
        offset_words: u32,
        #[serde(rename = "wordCount")]
        word_count: u16,
        #[serde(rename = "elementWidthBytes")]
        element_width_bytes: u16,
        #[serde(rename = "elementCount")]
        element_count: u32,
        #[serde(rename = "previewElements")]
        preview_elements: Vec<String>,
        #[serde(rename = "hexPreview")]
        hex_preview: String,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TryBlockJson {
    start_offset_word: u32,
    insn_count: u16,
    handlers: Vec<CatchHandlerJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CatchHandlerJson {
    type_descriptor: Option<String>,
    handler_offset_word: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CfgJson {
    blocks: Vec<BasicBlockJson>,
    edge_count: usize,
    branch_count: usize,
    exception_edge_count: usize,
    engine_label: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BasicBlockJson {
    id: String,
    index: usize,
    start_offset_words: u32,
    end_offset_words: u32,
    instruction_indices: Vec<usize>,
    terminator_kind: &'static str,
    is_entry: bool,
    is_exception_handler: bool,
    predecessors: Vec<String>,
    outgoing_edges: Vec<CfgEdgeJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CfgEdgeJson {
    from_block_id: String,
    to_block_id: String,
    to_offset_words: u32,
    kind: &'static str,
    label: String,
}

pub fn disassemble_method_to_json(
    dex: &DexFile,
    class_def_idx: u32,
    method_idx: u32,
) -> Option<String> {
    let cls = dex.get_class_def_full(class_def_idx)?;
    let method = cls
        .direct_methods
        .iter()
        .chain(cls.virtual_methods.iter())
        .find(|m| m.method_idx == method_idx)?;

    let (insns, try_blocks, cfg) = if let Some(ref code) = method.code {
        let code_bytes = dex.get_insns_bytes(code)?;
        let disasm = DalvikDisassembler::new(dex);
        let insns = disasm.disassemble_bytes(code_bytes);
        let tries = dex.get_try_blocks(code.code_item_offset);
        let cfg = MethodCfg::build_with_bytes_and_tries(&insns, code_bytes, &tries);
        (insns, tries, cfg)
    } else {
        (Vec::new(), Vec::new(), MethodCfg::build(&[]))
    };

    let json_insns = insns
        .iter()
        .map(|insn| to_instruction_json(dex, insn))
        .collect();
    let json_tries = try_blocks.iter().map(to_try_block_json).collect();
    let json_cfg = to_cfg_json(&cfg);

    let payload = MethodDisassemblyJson {
        instructions: json_insns,
        try_blocks: json_tries,
        cfg: json_cfg,
    };
    serde_json::to_string(&payload).ok()
}

fn to_instruction_json(dex: &DexFile, insn: &DalvikInstruction) -> InstructionJson {
    let is_payload = insn.group == OpcodeGroup::Payload;
    let is_range = matches!(
        insn.format,
        "3rc" | "4rcc" | "5rc" | "3rmi" | "3rms"
    );
    let is_list_format = is_range || matches!(insn.format, "35c" | "45cc" | "35mi" | "35ms");

    let (reg_a, reg_b, reg_c, reg_list) = if is_list_format {
        (None, None, None, insn.registers.clone())
    } else {
        (
            insn.registers.first().copied(),
            insn.registers.get(1).copied(),
            insn.registers.get(2).copied(),
            Vec::new(),
        )
    };

    let target_offset = insn
        .target_offset
        .map(|rel| insn.offset as i32 + rel);

    let mut string_ref = None;
    let mut type_ref = None;
    let mut field_ref = None;
    let mut method_ref = None;

    if let Some(idx) = insn.index {
        match insn.group {
            OpcodeGroup::Const
                if matches!(insn.mnemonic, "const-string" | "const-string/jumbo") =>
            {
                string_ref = dex.get_string(idx).map(|c| c.into_owned());
            }
            OpcodeGroup::Const
            | OpcodeGroup::CheckCast
            | OpcodeGroup::InstanceOf
            | OpcodeGroup::NewInstance
            | OpcodeGroup::NewArray
            | OpcodeGroup::FilledNewArray => {
                if !matches!(
                    insn.mnemonic,
                    "const-method-handle" | "const-method-type"
                ) {
                    type_ref = dex.get_type_descriptor(idx).map(|c| c.into_owned());
                }
            }
            OpcodeGroup::InstanceFieldGet
            | OpcodeGroup::InstanceFieldPut
            | OpcodeGroup::StaticFieldGet
            | OpcodeGroup::StaticFieldPut => {
                if let Some((cls, name, typ)) = dex.get_field_full(idx) {
                    field_ref = Some(FieldRefJson {
                        defining_class: cls.into_owned(),
                        field_type: typ.into_owned(),
                        name: name.into_owned(),
                    });
                }
            }
            OpcodeGroup::InvokeVirtual
            | OpcodeGroup::InvokeSuper
            | OpcodeGroup::InvokeDirect
            | OpcodeGroup::InvokeStatic
            | OpcodeGroup::InvokeInterface
            | OpcodeGroup::InvokeVirtualRange
            | OpcodeGroup::InvokeSuperRange
            | OpcodeGroup::InvokeDirectRange
            | OpcodeGroup::InvokeStaticRange
            | OpcodeGroup::InvokeInterfaceRange
            | OpcodeGroup::InvokePolymorphic
            | OpcodeGroup::InvokePolymorphicRange => {
                if let (Some(cls), Some(name), Some((shorty, ret, params))) = (
                    dex.get_method_class_desc(idx),
                    dex.get_method_name(idx),
                    dex.get_method_proto(idx),
                ) {
                    method_ref = Some(MethodRefJson {
                        defining_class: cls.into_owned(),
                        proto: ProtoJson {
                            shorty: shorty.into_owned(),
                            return_type: ret.into_owned(),
                            parameter_types: params.into_iter().map(|p| p.into_owned()).collect(),
                        },
                        name: name.into_owned(),
                    });
                }
            }
            _ => {}
        }
    }

    InstructionJson {
        offset_words: insn.offset,
        width_words: insn.length_units,
        opcode: if is_payload {
            insn.opcode
        } else {
            insn.opcode & 0xFF
        },
        mnemonic: insn.mnemonic,
        format: insn.format,
        operands_text: insn.operands_text.clone(),
        raw_words: insn.raw_words.clone(),
        category: to_kotlin_category(insn.group, insn.opcode),
        reg_a,
        reg_b,
        reg_c,
        reg_list,
        is_range_invoke: is_range,
        literal: insn.literal,
        target_offset,
        string_ref,
        type_ref,
        field_ref,
        method_ref,
        payload: insn.payload.as_ref().map(to_payload_json),
    }
}

fn to_kotlin_category(group: OpcodeGroup, opcode_word: u16) -> &'static str {
    match group {
        OpcodeGroup::Nop => "NOP",
        OpcodeGroup::Move => "MOVE",
        OpcodeGroup::Return => "RETURN",
        OpcodeGroup::Const => "CONST",
        OpcodeGroup::Monitor => "MONITOR",
        OpcodeGroup::CheckCast | OpcodeGroup::InstanceOf => "CHECK",
        OpcodeGroup::NewInstance | OpcodeGroup::NewArray | OpcodeGroup::FilledNewArray => "NEW",
        OpcodeGroup::ArrayLength
        | OpcodeGroup::FillArrayData
        | OpcodeGroup::ArrayGet
        | OpcodeGroup::ArrayPut => "ARRAY",
        OpcodeGroup::Throw => "THROW",
        OpcodeGroup::Goto
        | OpcodeGroup::PackedSwitch
        | OpcodeGroup::SparseSwitch
        | OpcodeGroup::IfTest
        | OpcodeGroup::IfTestZ => "BRANCH",
        OpcodeGroup::Cmp => "COMPARE",
        OpcodeGroup::InstanceFieldGet
        | OpcodeGroup::InstanceFieldPut
        | OpcodeGroup::StaticFieldGet
        | OpcodeGroup::StaticFieldPut => "FIELD",
        OpcodeGroup::InvokeVirtual
        | OpcodeGroup::InvokeSuper
        | OpcodeGroup::InvokeDirect
        | OpcodeGroup::InvokeStatic
        | OpcodeGroup::InvokeInterface
        | OpcodeGroup::InvokeVirtualRange
        | OpcodeGroup::InvokeSuperRange
        | OpcodeGroup::InvokeDirectRange
        | OpcodeGroup::InvokeStaticRange
        | OpcodeGroup::InvokeInterfaceRange
        | OpcodeGroup::InvokePolymorphic
        | OpcodeGroup::InvokePolymorphicRange
        | OpcodeGroup::InvokeCustom
        | OpcodeGroup::InvokeCustomRange => "INVOKE",
        OpcodeGroup::Unop if (0x81..=0x8F).contains(&(opcode_word & 0xFF)) => "CONVERT",
        OpcodeGroup::Unop
        | OpcodeGroup::Binop
        | OpcodeGroup::Binop2Addr
        | OpcodeGroup::BinopLit16
        | OpcodeGroup::BinopLit8 => "MATH",
        OpcodeGroup::Payload => "PAYLOAD",
        OpcodeGroup::Unknown => "UNKNOWN",
    }
}

fn to_payload_json(payload: &DalvikPayload) -> PayloadJson {
    match payload {
        DalvikPayload::PackedSwitch {
            offset_words,
            word_count,
            first_key,
            targets,
        } => PayloadJson::PackedSwitch {
            offset_words: *offset_words,
            word_count: *word_count,
            first_key: *first_key,
            target_offsets: targets.clone(),
        },
        DalvikPayload::SparseSwitch {
            offset_words,
            word_count,
            keys,
            targets,
        } => PayloadJson::SparseSwitch {
            offset_words: *offset_words,
            word_count: *word_count,
            keys: keys.clone(),
            target_offsets: targets.clone(),
        },
        DalvikPayload::FillArrayData {
            offset_words,
            word_count,
            element_width,
            element_count,
            preview_elements,
            hex_preview,
            ..
        } => PayloadJson::FillArrayData {
            offset_words: *offset_words,
            word_count: *word_count,
            element_width_bytes: *element_width,
            element_count: *element_count,
            preview_elements: preview_elements.clone(),
            hex_preview: hex_preview.clone(),
        },
    }
}

fn to_try_block_json(tb: &TryCatchBlock) -> TryBlockJson {
    TryBlockJson {
        start_offset_word: tb.start_pc,
        insn_count: tb.insn_count,
        handlers: tb
            .handlers
            .iter()
            .map(|h| CatchHandlerJson {
                type_descriptor: h.type_desc.clone(),
                handler_offset_word: h.handler_pc,
            })
            .collect(),
    }
}

fn to_cfg_json(cfg: &MethodCfg) -> CfgJson {
    let mut preds_by_block: HashMap<usize, Vec<String>> = HashMap::new();
    let mut seen_preds: HashMap<usize, HashSet<usize>> = HashMap::new();
    let mut outgoing_by_block: HashMap<usize, Vec<CfgEdgeJson>> = HashMap::new();

    for e in &cfg.edges {
        if seen_preds
            .entry(e.to_block)
            .or_default()
            .insert(e.from_block)
        {
            preds_by_block
                .entry(e.to_block)
                .or_default()
                .push(format!("BB_{}", e.from_block));
        }
        outgoing_by_block
            .entry(e.from_block)
            .or_default()
            .push(CfgEdgeJson {
                from_block_id: format!("BB_{}", e.from_block),
                to_block_id: format!("BB_{}", e.to_block),
                to_offset_words: e.to_offset,
                kind: match e.kind {
                    EdgeKind::Fallthrough => "FALLTHROUGH",
                    EdgeKind::Branch => "CONDITIONAL_BRANCH",
                    EdgeKind::SwitchCase => "SWITCH_CASE",
                    EdgeKind::Catch => "EXCEPTION_HANDLER",
                },
                label: e.label.clone(),
            });
    }

    let blocks = cfg
        .blocks
        .iter()
        .map(|b| {
            let mut outgoing = outgoing_by_block.remove(&b.id).unwrap_or_default();
            if b.terminator_kind == BlockTerminatorKind::UnconditionalJump {
                for edge in &mut outgoing {
                    if edge.kind == "CONDITIONAL_BRANCH" {
                        edge.kind = "UNCONDITIONAL_JUMP";
                    }
                }
            }
            BasicBlockJson {
                id: format!("BB_{}", b.id),
                index: b.id,
                start_offset_words: b.start_offset,
                end_offset_words: b.end_offset_words,
                instruction_indices: b.instruction_indices.clone(),
                terminator_kind: match b.terminator_kind {
                    BlockTerminatorKind::Entry => "ENTRY",
                    BlockTerminatorKind::Fallthrough => "FALLTHROUGH",
                    BlockTerminatorKind::ConditionalBranch => "CONDITIONAL_BRANCH",
                    BlockTerminatorKind::UnconditionalJump => "UNCONDITIONAL_JUMP",
                    BlockTerminatorKind::Switch => "SWITCH",
                    BlockTerminatorKind::Return => "RETURN",
                    BlockTerminatorKind::Throw => "THROW",
                    BlockTerminatorKind::ExceptionHandler => "EXCEPTION_HANDLER",
                },
                is_entry: b.is_entry,
                is_exception_handler: b.is_exception_handler,
                predecessors: preds_by_block.remove(&b.id).unwrap_or_default(),
                outgoing_edges: outgoing,
            }
        })
        .collect();

    CfgJson {
        blocks,
        edge_count: cfg.edges.len(),
        branch_count: cfg.branch_count,
        exception_edge_count: cfg.exception_edge_count,
        engine_label: cfg.engine_label.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dex_parser::{BuiltClass, BuiltCode, BuiltMethod, BuiltTry, DexBuilder};

    #[test]
    fn test_disassemble_method_to_json_with_try_catch_and_branch() {
        let mut b = DexBuilder::new();
        // Intern all class, proto, method, and catch-handler types before reading pool indices.
        b.intern_type("Lcom/example/CfgDemo;");
        b.intern_type("Ljava/lang/Object;");
        b.intern_type("Ljava/lang/Exception;");
        b.intern_method_ref("Lcom/example/CfgDemo;", "branchAndCatch", "(I)I");
        let exc_type_idx = b.pool_maps().ty("Ljava/lang/Exception;").unwrap();

        b.add_class(BuiltClass {
            descriptor: "Lcom/example/CfgDemo;".into(),
            access_flags: 1,
            superclass: Some("Ljava/lang/Object;".into()),
            interfaces: vec![],
            source_file: None,
            static_fields: vec![],
            instance_fields: vec![],
            direct_methods: vec![BuiltMethod {
                class: "Lcom/example/CfgDemo;".into(),
                name: "branchAndCatch".into(),
                proto: "(I)I".into(),
                access_flags: 9,
                direct: true,
                code: Some(BuiltCode {
                    registers_size: 2,
                    ins_size: 1,
                    outs_size: 0,
                    // 0x00: if-eqz v1, +3 (target word 3) -> 38 01 03 00
                    // 0x02: return v1                       -> 0f 01
                    // 0x03: const/4 v0, #1                  -> 12 10
                    // 0x04: int-to-long v0, v1              -> 81 10
                    // 0x05: return v0                       -> 0f 00
                    insns: vec![
                        0x38, 0x01, 0x03, 0x00,
                        0x0f, 0x01,
                        0x12, 0x10,
                        0x81, 0x10,
                        0x0f, 0x00,
                    ],
                    tries: vec![BuiltTry {
                        start_unit: 0,
                        insn_count: 3,
                        handlers: vec![(exc_type_idx, 3)],
                        catch_all: None,
                    }],
                    debug_info_off: 0,
                    debug_ops: vec![],
                }),
            }],
            virtual_methods: vec![],
            annotations: Default::default(),
        });

        let raw = b.finish().expect("valid DEX");
        let dex = DexFile::parse(&raw).expect("parse DEX");
        let cls = dex.get_class_def_full(0).unwrap();
        let m_idx = cls.direct_methods[0].method_idx;

        let json_str = disassemble_method_to_json(&dex, 0, m_idx).expect("JSON output");
        let v: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");

        let insns = v["instructions"].as_array().unwrap();
        assert_eq!(insns.len(), 5);
        assert_eq!(insns[0]["mnemonic"], "if-eqz");
        assert_eq!(insns[0]["targetOffset"], 3);
        assert_eq!(insns[2]["mnemonic"], "const/4");
        assert_eq!(insns[3]["mnemonic"], "int-to-long");
        assert_eq!(insns[3]["category"], "CONVERT");

        let tries = v["tryBlocks"].as_array().unwrap();
        assert_eq!(tries.len(), 1);
        assert_eq!(tries[0]["handlers"][0]["typeDescriptor"], "Ljava/lang/Exception;");
        assert_eq!(tries[0]["handlers"][0]["handlerOffsetWord"], 3);

        let blocks = v["cfg"]["blocks"].as_array().unwrap();
        assert!(blocks.len() >= 2);
        assert_eq!(v["cfg"]["exceptionEdgeCount"].as_u64().unwrap(), 2);
    }
}
