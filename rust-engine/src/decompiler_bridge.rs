//! Pure-Rust DEX to Java decompiler bridge backed by `androguard/dex-decompiler`
//! (`DecompilationMode::Restructure`) with optional `axml_parser::ARSCParser`
//! `R.type.name` resource ID resolution.

use crate::dex::DexFile;
use axml_parser::ARSCParser;
use dex_decompiler::{
    java, ClassDef, DecompilationMode, Decompiler, DecompilerOptions, EncodedMethod,
};
use std::collections::HashMap;

/// Parses `resources.arsc` bytes into an ID -> `R.type.name` lookup table.
pub fn build_arsc_resource_map(arsc_bytes: Option<&[u8]>) -> Option<HashMap<u32, String>> {
    let bytes = arsc_bytes.filter(|b| b.len() >= 12)?;
    let parser = ARSCParser::new(bytes).ok()?;
    let map = parser.id_to_java_name();
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

/// Decompiles a single Dalvik method (`class_def_idx`, `method_idx`) into restructured Java source.
pub fn decompile_method_java(
    dex: &DexFile,
    class_def_idx: u32,
    method_idx: u32,
    arsc_bytes: Option<&[u8]>,
) -> Option<String> {
    let (class_def, full_class_name, simple_class_name) =
        resolve_class_meta(dex, class_def_idx)?;
    let class_data = dex.inner.get_class_data(&class_def).ok()??;
    let encoded: &EncodedMethod = class_data
        .direct_methods
        .iter()
        .chain(class_data.virtual_methods.iter())
        .find(|m| m.method_idx == method_idx)?;

    let decompiler = Decompiler::with_options(&dex.inner, build_options(arsc_bytes));
    let raw_java = decompiler
        .decompile_method(encoded, Some(&simple_class_name), Some(&full_class_name))
        .ok()?;
    let dedented = dedent_four_spaces(&raw_java);
    let trimmed = dedented.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Decompiles an entire DEX class (`class_def_idx`) into restructured Java source.
pub fn decompile_class_java(
    dex: &DexFile,
    class_def_idx: u32,
    arsc_bytes: Option<&[u8]>,
) -> Option<String> {
    let class_def = dex.inner.get_class_def(class_def_idx).ok()?;
    let decompiler = Decompiler::with_options(&dex.inner, build_options(arsc_bytes));
    let java_src = decompiler.decompile_class(&class_def).ok()?;
    let trimmed = java_src.trim_end();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn build_options(arsc_bytes: Option<&[u8]>) -> DecompilerOptions {
    DecompilerOptions {
        mode: DecompilationMode::Restructure,
        use_debug_names: true,
        resource_map: build_arsc_resource_map(arsc_bytes),
        ..Default::default()
    }
}

fn resolve_class_meta(dex: &DexFile, class_def_idx: u32) -> Option<(ClassDef, String, String)> {
    let class_def = dex.inner.get_class_def(class_def_idx).ok()?;
    let class_type = dex.inner.get_type(class_def.class_idx).ok()?;
    let full_class_name = java::descriptor_to_java(&class_type);
    let simple_raw = full_class_name
        .rsplit_once('.')
        .map(|(_, c)| c)
        .unwrap_or(&full_class_name);
    let simple_name = simple_raw
        .rsplit_once('$')
        .map(|(_, s)| s)
        .unwrap_or(simple_raw)
        .to_string();
    Some((class_def, full_class_name, simple_name))
}

fn dedent_four_spaces(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (idx, line) in text.lines().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        let stripped = line.strip_prefix("    ").unwrap_or(line);
        out.push_str(stripped);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axml_parser::{build_arsc, ArscBuildConfig, ArscBuildEntry, ArscBuildInput, ArscBuildType, ArscBuildValue};
    use dex_parser::{BuiltClass, BuiltCode, BuiltMethod, DexBuilder};

    fn build_sample_decompiler_dex() -> DexFile {
        let mut b = DexBuilder::new();
        b.add_class(BuiltClass {
            descriptor: "Lcom/example/DecompileSample;".into(),
            access_flags: 0x0001, // public
            superclass: Some("Ljava/lang/Object;".into()),
            interfaces: vec![],
            source_file: Some("DecompileSample.java".into()),
            static_fields: vec![],
            instance_fields: vec![],
            direct_methods: vec![
                BuiltMethod {
                    class: "Lcom/example/DecompileSample;".into(),
                    name: "getTitleRes".into(),
                    proto: "()I".into(),
                    access_flags: 0x0009, // public static
                    direct: true,
                    code: Some(BuiltCode {
                        registers_size: 1,
                        ins_size: 0,
                        outs_size: 0,
                        insns: vec![
                            0x14, 0x00, 0x00, 0x00, 0x01, 0x7f, // const v0, 0x7f010000
                            0x0f, 0x00,                         // return v0
                        ],
                        tries: vec![],
                        debug_info_off: 0,
                        debug_ops: vec![],
                    }),
                },
                BuiltMethod {
                    class: "Lcom/example/DecompileSample;".into(),
                    name: "isPositive".into(),
                    proto: "(I)Z".into(),
                    access_flags: 0x0009, // public static
                    direct: true,
                    code: Some(BuiltCode {
                        registers_size: 2,
                        ins_size: 1,
                        outs_size: 0,
                        insns: vec![
                            0x3d, 0x01, 0x04, 0x00, // if-lez v1, +4 (word 4)
                            0x12, 0x10,             // const/4 v0, #1
                            0x0f, 0x00,             // return v0
                            0x12, 0x00,             // const/4 v0, #0
                            0x0f, 0x00,             // return v0
                        ],
                        tries: vec![],
                        debug_info_off: 0,
                        debug_ops: vec![],
                    }),
                },
            ],
            virtual_methods: vec![],
            annotations: Default::default(),
        });
        let raw = b.finish().expect("valid DEX");
        DexFile::parse(&raw).expect("parse DEX")
    }

    fn build_sample_arsc() -> Vec<u8> {
        build_arsc(&ArscBuildInput {
            package_id: 0x7f,
            package_name: "com.example".into(),
            types: vec![ArscBuildType {
                name: "string".into(),
                type_id: 1,
                configs: vec![ArscBuildConfig {
                    qualifier: String::new(),
                    raw: None,
                    entries: vec![ArscBuildEntry {
                        entry_index: 0,
                        name: "sample_title".into(),
                        value: ArscBuildValue::String("Hello Sample".into()),
                        public: true,
                    }],
                }],
            }],
        })
        .expect("build sample arsc")
    }

    #[test]
    fn test_decompile_sample_method_and_class_with_arsc_resolution() {
        let dex = build_sample_decompiler_dex();
        let cls = dex.get_class_def_full(0).expect("class def 0");
        let arsc = build_sample_arsc();

        let is_positive = cls
            .direct_methods
            .iter()
            .find(|m| m.name == "isPositive")
            .expect("isPositive method");
        let title_res = cls
            .direct_methods
            .iter()
            .find(|m| m.name == "getTitleRes")
            .expect("getTitleRes method");

        let method_java =
            decompile_method_java(&dex, 0, is_positive.method_idx, Some(&arsc))
                .expect("decompile isPositive");
        assert!(
            method_java.contains("public static boolean isPositive("),
            "unexpected method signature:\n{}",
            method_java
        );
        assert!(
            method_java.contains("return")
                && (method_java.contains("if (") || method_java.contains("? ")),
            "expected restructured conditional/return control flow:\n{}",
            method_java
        );

        let title_java =
            decompile_method_java(&dex, 0, title_res.method_idx, Some(&arsc))
                .expect("decompile getTitleRes");
        assert!(
            title_java.contains("R.string.sample_title"),
            "expected ARSC resource replacement R.string.sample_title:\n{}",
            title_java
        );

        let class_java = decompile_class_java(&dex, 0, Some(&arsc)).expect("decompile class");
        assert!(
            class_java.contains("public class DecompileSample"),
            "expected class declaration:\n{}",
            class_java
        );
        assert!(
            class_java.contains("R.string.sample_title"),
            "expected ARSC replacement inside class Java:\n{}",
            class_java
        );

        // Missing indices return None cleanly without panicking.
        assert!(decompile_method_java(&dex, 999, 0, None).is_none());
        assert!(decompile_class_java(&dex, 999, None).is_none());
    }
}
