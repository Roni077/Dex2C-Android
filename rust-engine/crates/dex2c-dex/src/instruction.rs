//! Dalvik bytecode instructions, opcode definitions, operands, payload structures, and try/catch metadata.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpcodeGroup {
    Move,
    Return,
    Const,
    Monitor,
    CheckCast,
    InstanceOf,
    ArrayLength,
    NewInstance,
    NewArray,
    FilledNewArray,
    FillArrayData,
    Throw,
    Goto,
    PackedSwitch,
    SparseSwitch,
    Cmp,
    IfTest,
    IfTestZ,
    ArrayGet,
    ArrayPut,
    InstanceFieldGet,
    InstanceFieldPut,
    StaticFieldGet,
    StaticFieldPut,
    InvokeVirtual,
    InvokeSuper,
    InvokeDirect,
    InvokeStatic,
    InvokeInterface,
    InvokeVirtualRange,
    InvokeSuperRange,
    InvokeDirectRange,
    InvokeStaticRange,
    InvokeInterfaceRange,
    InvokePolymorphic,
    InvokePolymorphicRange,
    InvokeCustom,
    InvokeCustomRange,
    Unop,
    Binop,
    Binop2Addr,
    BinopLit16,
    BinopLit8,
    Nop,
    Payload,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DalvikPayload {
    PackedSwitch {
        offset_words: u32,
        word_count: u16,
        first_key: i32,
        targets: Vec<i32>,
    },
    SparseSwitch {
        offset_words: u32,
        word_count: u16,
        keys: Vec<i32>,
        targets: Vec<i32>,
    },
    FillArrayData {
        offset_words: u32,
        word_count: u16,
        element_width: u16,
        element_count: u32,
        data: Vec<u8>,
        preview_elements: Vec<String>,
        hex_preview: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct DalvikInstruction {
    pub offset: u32, // 16-bit code unit offset
    pub opcode: u16, // full first 16-bit word
    pub mnemonic: &'static str,
    pub format: &'static str,
    pub operands_text: String,
    pub raw_words: Vec<u16>,
    pub group: OpcodeGroup,
    pub length_units: u16, // length in 16-bit code units
    pub registers: Vec<u16>,
    pub literal: Option<i64>,
    pub target_offset: Option<i32>, // signed relative offset in 16-bit code units
    pub index: Option<u32>,         // string, type, field, method, proto, or call-site index
    pub payload: Option<DalvikPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatchHandler {
    pub type_desc: Option<String>, // None = catch-all (<all>)
    pub handler_pc: u32,           // 16-bit code unit offset
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TryCatchBlock {
    pub start_pc: u32,
    pub end_pc: u32,
    pub insn_count: u16,
    pub handlers: Vec<CatchHandler>,
    pub catch_all_pc: Option<u32>,
}
