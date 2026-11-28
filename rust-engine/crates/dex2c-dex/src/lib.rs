//! DEX and Dalvik processing crate root for `dex2c-dex`.

pub mod cfg;
pub mod disassembler;
pub mod filter;
pub mod instruction;
pub mod parser;
pub mod patcher;
pub mod verifier;

pub use cfg::{BasicBlock, BlockTerminatorKind, CfgEdge, EdgeKind, MethodCfg};
pub use disassembler::DalvikDisassembler;
pub use filter::{evaluate_dex_methods, evaluate_dex_methods_and_classes, CompiledFilter, FilterMatchResult};
pub use instruction::{CatchHandler, DalvikInstruction, DalvikPayload, OpcodeGroup, TryCatchBlock};
pub use parser::{
    ClassMethodSummary, DexClassDefFull, DexCodeMeta, DexFieldMeta, DexFile, DexHeader,
    DexMethodMeta,
};
pub use patcher::{patch_dex_methods_native, resign_dex_header, ACC_NATIVE};
pub use verifier::{
    verify_dex_class, verify_dex_class_json, verify_dex_method, verify_dex_method_json,
    MethodVerificationIssue, MethodVerificationReport, RegType,
};
