//! DEX to Java decompiler in pure Rust.
//! Uses dex-bytecode for Dalvik instruction disassembly and dex-parser for DEX parsing.

pub mod decompile;
pub mod emulator;
pub mod error;
pub mod java;
pub mod xref;

pub use decompile::deobf::{build_deobf_rename_map, merge_rename_maps, DeobfuscateOptions};
pub use decompile::json_export::{ClassJson, DexJsonExport, FieldJson, MethodJson};
pub use decompile::mapping::{
    load_mapping_file, load_mapping_str, mapping_format_from_path, save_mapping_file,
    save_mapping_str, MappingFormat,
};
pub use decompile::value_flow::{ValueFlowAnalysis, ValueFlowAnalysisOwned, ValueFlowResult};
pub use decompile::{
    class_name_to_path, rename::RenameMap, CfgEdgeInfo, CfgNodeInfo, DecompilationMode, Decompiler,
    DecompilerOptions, MethodBytecodeRow,
};
pub use dex_parser::{ClassDef, CodeItem, DexFile, EncodedMethod};
pub use error::{DexDecompilerError, Result};
pub use xref::{
    find_extends, find_field_xrefs, find_field_xrefs_fast, find_impls, find_method_call_traces,
    find_method_call_traces_by_class_method, find_method_call_traces_with_index, find_method_callees,
    find_method_callees_by_class_method, find_method_callers, find_method_callers_by_class_method,
    find_method_callers_by_name, find_method_callers_fast, find_method_xrefs_fast,
    find_string_xrefs, find_type_xrefs, findrefs_kind, findrefs_kind_on_bytes,
    findrefs_kind_on_dexes, hierarchy_as_sites, CallTraceFrame, CallTracePath, FastRefSite,
    FieldXref, FieldXrefsInfo, MethodCallTracesInfo, MethodCallee, MethodCalleesInfo, MethodCaller,
    MethodCallersInfo, ReverseCallIndex,
};

/// Parse a DEX file from raw bytes. Returns decompiler Result (maps parser errors to Parse).
pub fn parse_dex(data: &[u8]) -> Result<DexFile> {
    DexFile::parse(data).map_err(|e| DexDecompilerError::Parse(e.to_string()))
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn parse_empty_fails() {
        let r = parse_dex(&[]);
        assert!(r.is_err());
    }

    #[test]
    fn parse_garbage_fails() {
        let r = parse_dex(b"not a DEX file!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        assert!(r.is_err());
    }
}
