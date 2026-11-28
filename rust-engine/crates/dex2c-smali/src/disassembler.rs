//! Smali disassembler formatting Dalvik classes and bytecode into Google-compatible Smali format.

use dex2c_dex::{
    DalvikDisassembler, DalvikInstruction, DexClassDefFull, DexFile, DexMethodMeta, OpcodeGroup,
};
use std::fmt::Write;

pub struct SmaliDisassembler;

impl SmaliDisassembler {
    pub fn disassemble_class(dex: &DexFile, class_def: &DexClassDefFull<'_>) -> String {
        let mut out = String::with_capacity(4096);

        let flags_str = format_access_flags(class_def.access_flags);
        if flags_str.is_empty() {
            let _ = writeln!(out, ".class {}", class_def.descriptor);
        } else {
            let _ = writeln!(out, ".class {} {}", flags_str, class_def.descriptor);
        }

        if let Some(ref super_desc) = class_def.superclass {
            let _ = writeln!(out, ".super {}", super_desc);
        } else {
            let _ = writeln!(out, ".super Ljava/lang/Object;");
        }

        if let Some(ref source) = class_def.source_file {
            let _ = writeln!(out, ".source \"{}\"", escape_smali_string(source));
        }

        for iface in &class_def.interfaces {
            let _ = writeln!(out, ".implements {}", iface);
        }

        out.push('\n');

        for f in class_def
            .static_fields
            .iter()
            .chain(class_def.instance_fields.iter())
        {
            let f_flags = format_field_access_flags(f.access_flags, f.is_static);
            let _ = writeln!(out, ".field {} {}:{}", f_flags, f.name, f.type_desc);
        }

        if !class_def.static_fields.is_empty() || !class_def.instance_fields.is_empty() {
            out.push('\n');
        }

        let disasm = DalvikDisassembler::new(dex);
        for m in class_def
            .direct_methods
            .iter()
            .chain(class_def.virtual_methods.iter())
        {
            Self::disassemble_method(&mut out, &disasm, dex, m);
            out.push('\n');
        }

        out
    }

    fn disassemble_method(
        out: &mut String,
        disasm: &DalvikDisassembler<'_>,
        dex: &DexFile,
        m: &DexMethodMeta<'_>,
    ) {
        let flags_str = format_method_access_flags(m.access_flags, m.is_direct);
        let params_str = m.param_types.join("");
        let _ = writeln!(
            out,
            ".method {} {}({}){}",
            flags_str, m.name, params_str, m.return_type
        );

        if let Some(ref code) = m.code {
            let _ = writeln!(out, "    .registers {}", code.registers_size);

            if let Some(bytes) = dex.get_insns_bytes(code) {
                let insns = disasm.disassemble_bytes(bytes);
                for insn in &insns {
                    Self::format_instruction(out, dex, insn);
                }
            }
        }

        let _ = writeln!(out, ".end method");
    }

    fn format_instruction(out: &mut String, dex: &DexFile, insn: &DalvikInstruction) {
        if insn.group == OpcodeGroup::Payload {
            let _ = writeln!(
                out,
                "    # :offset_{:04x} {} ({})",
                insn.offset, insn.mnemonic, insn.operands_text
            );
            return;
        }

        let _ = write!(out, "    {:18}", insn.mnemonic);

        if !insn.operands_text.is_empty() && insn.target_offset.is_none() {
            let _ = writeln!(out, " {}", insn.operands_text);
            return;
        }

        if !insn.registers.is_empty() {
            let regs: Vec<String> = insn.registers.iter().map(|r| format!("v{}", r)).collect();
            let _ = write!(out, " {}", regs.join(", "));
        }

        if let Some(lit) = insn.literal {
            if !insn.registers.is_empty() {
                out.push_str(", ");
            }
            let _ = write!(out, "{:#x}", lit);
        }

        if let Some(target) = insn.target_offset {
            if !insn.registers.is_empty() || insn.literal.is_some() {
                out.push_str(", ");
            }
            let target_pc = insn.offset as i32 + target;
            let _ = write!(out, ":offset_{:04x}", target_pc);
        } else if let Some(idx) = insn.index {
            if !insn.registers.is_empty() || insn.literal.is_some() {
                out.push_str(", ");
            }
            match insn.group {
                OpcodeGroup::Const if matches!(insn.mnemonic, "const-string" | "const-string/jumbo") => {
                    let s = dex.get_string(idx);
                    let _ = write!(out, "\"{}\"", escape_smali_string(s.as_deref().unwrap_or("")));
                }
                OpcodeGroup::Const | OpcodeGroup::CheckCast | OpcodeGroup::InstanceOf
                | OpcodeGroup::NewInstance | OpcodeGroup::NewArray | OpcodeGroup::FilledNewArray => {
                    let t = dex.get_type_descriptor(idx);
                    let _ = write!(out, "{}", t.as_deref().unwrap_or("Ljava/lang/Object;"));
                }
                OpcodeGroup::InstanceFieldGet
                | OpcodeGroup::InstanceFieldPut
                | OpcodeGroup::StaticFieldGet
                | OpcodeGroup::StaticFieldPut => {
                    if let Some((cls, name, typ)) = dex.get_field_full(idx) {
                        let _ = write!(out, "{}->{}:{}", cls, name, typ);
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
                | OpcodeGroup::InvokeInterfaceRange => {
                    if let Some(name) = dex.get_method_name(idx) {
                        let class_desc = dex.get_method_class_desc(idx);
                        let proto = dex.get_method_proto(idx);
                        let params = proto
                            .as_ref()
                            .map(|p| p.2.join(""))
                            .unwrap_or_default();
                        let ret = proto.as_ref().map(|p| p.1.as_ref()).unwrap_or("V");
                        let _ = write!(
                            out,
                            "{}->{}({}){}",
                            class_desc.as_deref().unwrap_or(""),
                            name,
                            params,
                            ret
                        );
                    }
                }
                _ => {
                    let _ = write!(out, "{:#x}", idx);
                }
            }
        }

        out.push('\n');
    }
}

fn format_access_flags(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & 0x0001 != 0 { parts.push("public"); }
    if flags & 0x0002 != 0 { parts.push("private"); }
    if flags & 0x0004 != 0 { parts.push("protected"); }
    if flags & 0x0008 != 0 { parts.push("static"); }
    if flags & 0x0010 != 0 { parts.push("final"); }
    if flags & 0x0200 != 0 { parts.push("interface"); }
    if flags & 0x0400 != 0 { parts.push("abstract"); }
    if flags & 0x1000 != 0 { parts.push("synthetic"); }
    if flags & 0x2000 != 0 { parts.push("annotation"); }
    if flags & 0x4000 != 0 { parts.push("enum"); }
    parts.join(" ")
}

fn format_field_access_flags(flags: u32, is_static: bool) -> String {
    let mut s = format_access_flags(flags);
    if is_static && !s.contains("static") {
        if !s.is_empty() { s.push(' '); }
        s.push_str("static");
    }
    s
}

fn format_method_access_flags(flags: u32, is_direct: bool) -> String {
    let mut s = format_access_flags(flags);
    if is_direct && (flags & 0x0008 != 0) && !s.contains("static") {
        if !s.is_empty() { s.push(' '); }
        s.push_str("static");
    }
    s
}

fn escape_smali_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
