//! D2CN v1 packed binary serializer and descriptor/package-tree helpers for Dex2C Studio.
//! DEX parsing is delegated entirely to `dex2c_dex::DexFile` (`androguard/dex-parser`).

pub use dex2c_dex::{
    ClassMethodSummary, DexClassDefFull, DexCodeMeta, DexFieldMeta, DexFile, DexHeader,
    DexMethodMeta,
};
use std::borrow::Cow;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PackageTreeNode<'a> {
    pub package_name: &'a str,
    pub display_label: &'a str,
    pub depth: u16,
    pub parent_idx: u32,
    pub direct_classes: Vec<u32>,
    pub total_subtree_classes: u32,
    pub total_bytecode_methods: u32,
    pub children: Vec<u32>,
}

/// Packs all class definitions, methods, fields, and string pool into the D2CN v1 binary buffer.
pub fn pack_dex_classes(dex: &DexFile) -> Vec<u8> {
    let class_count = dex.header.class_defs_size;
    let mut classes = Vec::with_capacity(class_count as usize);
    let mut total_methods = 0u32;

    for i in 0..class_count {
        if let Some(cls) = dex.get_class_def_full(i) {
            total_methods += (cls.direct_methods.len() + cls.virtual_methods.len()) as u32;
            classes.push(cls);
        }
    }

    let mut pool = StringPool::new();

    struct ClassIndices {
        descriptor_idx: u32,
        full_name_idx: i32,
        pkg_name_idx: i32,
        simple_name_idx: i32,
        superclass_idx: i32,
        source_file_idx: i32,
        interface_indices: Vec<u32>,
        static_field_indices: Vec<(u32, u32)>,
        instance_field_indices: Vec<(u32, u32)>,
        direct_method_indices: Vec<(u32, u32, u32, Vec<u32>)>,
        virtual_method_indices: Vec<(u32, u32, u32, Vec<u32>)>,
    }

    let mut pre_indexed = Vec::with_capacity(classes.len());

    for cls in &classes {
        let desc_idx = pool.intern_cow(cls.descriptor.clone());

        let (full_name, pkg_name, simple_name) = parse_class_descriptor(&cls.descriptor);
        let full_name_idx = pool.intern_owned(full_name) as i32;
        let pkg_name_idx = pool.intern_owned(pkg_name) as i32;
        let simple_name_idx = pool.intern_owned(simple_name) as i32;

        let superclass_idx = cls
            .superclass
            .as_ref()
            .map(|s| pool.intern_cow(s.clone()) as i32)
            .unwrap_or(-1);
        let source_file_idx = cls
            .source_file
            .as_ref()
            .map(|s| pool.intern_cow(s.clone()) as i32)
            .unwrap_or(-1);

        let mut interface_indices = Vec::with_capacity(cls.interfaces.len());
        for iface in &cls.interfaces {
            interface_indices.push(pool.intern_cow(iface.clone()));
        }

        let mut static_field_indices = Vec::with_capacity(cls.static_fields.len());
        for f in &cls.static_fields {
            let n_idx = pool.intern_cow(f.name.clone());
            let t_idx = pool.intern_cow(f.type_desc.clone());
            static_field_indices.push((n_idx, t_idx));
        }

        let mut instance_field_indices = Vec::with_capacity(cls.instance_fields.len());
        for f in &cls.instance_fields {
            let n_idx = pool.intern_cow(f.name.clone());
            let t_idx = pool.intern_cow(f.type_desc.clone());
            instance_field_indices.push((n_idx, t_idx));
        }

        let mut direct_method_indices = Vec::with_capacity(cls.direct_methods.len());
        for m in &cls.direct_methods {
            let n_idx = pool.intern_cow(m.name.clone());
            let s_idx = pool.intern_cow(m.shorty.clone());
            let r_idx = pool.intern_cow(m.return_type.clone());
            let mut p_indices = Vec::with_capacity(m.param_types.len());
            for p in &m.param_types {
                p_indices.push(pool.intern_cow(p.clone()));
            }
            direct_method_indices.push((n_idx, s_idx, r_idx, p_indices));
        }

        let mut virtual_method_indices = Vec::with_capacity(cls.virtual_methods.len());
        for m in &cls.virtual_methods {
            let n_idx = pool.intern_cow(m.name.clone());
            let s_idx = pool.intern_cow(m.shorty.clone());
            let r_idx = pool.intern_cow(m.return_type.clone());
            let mut p_indices = Vec::with_capacity(m.param_types.len());
            for p in &m.param_types {
                p_indices.push(pool.intern_cow(p.clone()));
            }
            virtual_method_indices.push((n_idx, s_idx, r_idx, p_indices));
        }

        pre_indexed.push(ClassIndices {
            descriptor_idx: desc_idx,
            full_name_idx,
            pkg_name_idx,
            simple_name_idx,
            superclass_idx,
            source_file_idx,
            interface_indices,
            static_field_indices,
            instance_field_indices,
            direct_method_indices,
            virtual_method_indices,
        });
    }

    let mut writer = BufferWriter::new(64 * 1024);

    // Header: 32 bytes (0x20)
    writer.write_u32(0x4E433244); // 'D','2','C','N' LE
    writer.write_u16(1);          // version 1
    writer.write_u16(0);          // flags 0
    writer.write_u32(32);         // header_size
    writer.write_u32(pool.entries.len() as u32);
    writer.write_u32(classes.len() as u32);
    writer.write_u32(total_methods);
    writer.write_u32(32);         // string_pool_off
    let classes_off_pos = writer.len();
    writer.write_u32(0);          // classes_off placeholder

    // String pool
    for s in &pool.entries {
        let bytes = s.as_bytes();
        let len = bytes.len().min(u16::MAX as usize) as u16;
        writer.write_u16(len);
        writer.write_bytes(&bytes[..len as usize]);
    }

    // Patch classes_off
    let classes_off = writer.len() as u32;
    writer.patch_u32(classes_off_pos, classes_off);

    // Serialize Class Records
    for (i, cls) in classes.iter().enumerate() {
        let idxs = &pre_indexed[i];

        writer.write_u32(cls.class_def_idx);
        writer.write_u32(cls.access_flags);
        writer.write_u32(idxs.descriptor_idx);
        writer.write_i32(idxs.full_name_idx);
        writer.write_i32(idxs.pkg_name_idx);
        writer.write_i32(idxs.simple_name_idx);
        writer.write_i32(idxs.superclass_idx);
        writer.write_i32(idxs.source_file_idx);
        writer.write_u32(cls.annotations_off);
        writer.write_u32(cls.static_values_off);
        writer.write_u32(cls.class_data_off);

        writer.write_u16(idxs.interface_indices.len() as u16);
        for &iface_idx in &idxs.interface_indices {
            writer.write_u32(iface_idx);
        }

        writer.write_u16(cls.static_fields.len() as u16);
        for (f_idx, f) in cls.static_fields.iter().enumerate() {
            let (n_idx, t_idx) = idxs.static_field_indices[f_idx];
            writer.write_u32(f.field_idx);
            writer.write_u32(f.access_flags);
            writer.write_u32(n_idx);
            writer.write_u32(t_idx);
        }

        writer.write_u16(cls.instance_fields.len() as u16);
        for (f_idx, f) in cls.instance_fields.iter().enumerate() {
            let (n_idx, t_idx) = idxs.instance_field_indices[f_idx];
            writer.write_u32(f.field_idx);
            writer.write_u32(f.access_flags);
            writer.write_u32(n_idx);
            writer.write_u32(t_idx);
        }

        writer.write_u16(cls.direct_methods.len() as u16);
        for (m_idx, m) in cls.direct_methods.iter().enumerate() {
            let (n_idx, s_idx, r_idx, ref p_idxs) = idxs.direct_method_indices[m_idx];
            write_method_record(&mut writer, m, n_idx, s_idx, r_idx, p_idxs);
        }

        writer.write_u16(cls.virtual_methods.len() as u16);
        for (m_idx, m) in cls.virtual_methods.iter().enumerate() {
            let (n_idx, s_idx, r_idx, ref p_idxs) = idxs.virtual_method_indices[m_idx];
            write_method_record(&mut writer, m, n_idx, s_idx, r_idx, p_idxs);
        }
    }

    writer.into_vec()
}

fn write_method_record(
    writer: &mut BufferWriter,
    m: &DexMethodMeta<'_>,
    n_idx: u32,
    s_idx: u32,
    r_idx: u32,
    p_idxs: &[u32],
) {
    writer.write_u32(m.method_idx);
    writer.write_u32(m.access_flags);
    writer.write_u32(n_idx);
    writer.write_u32(s_idx);
    writer.write_u32(r_idx);
    writer.write_u16(p_idxs.len() as u16);
    for &p in p_idxs {
        writer.write_u32(p);
    }

    if let Some(ref code) = m.code {
        writer.write_u8(1);
        writer.write_u16(code.registers_size);
        writer.write_u16(code.ins_size);
        writer.write_u16(code.outs_size);
        writer.write_u16(code.tries_size);
        writer.write_u32(code.insns_count);
        writer.write_u32(code.insns_offset_bytes);
        writer.write_u32(code.code_item_offset);
        writer.write_u32(code.debug_info_offset);
    } else {
        writer.write_u8(0);
    }
}

#[inline]
pub fn extract_package_and_simple_name(desc: &str) -> (&str, &str) {
    let s = desc.strip_prefix('L').unwrap_or(desc);
    let s = s.strip_suffix(';').unwrap_or(s);
    if let Some(idx) = s.rfind('/') {
        (&s[..idx], &s[idx + 1..])
    } else {
        ("", s)
    }
}

pub fn parse_class_descriptor(desc: &str) -> (String, String, String) {
    let (pkg_slice, simple_slice) = extract_package_and_simple_name(desc);
    if pkg_slice.is_empty() {
        (
            simple_slice.to_string(),
            "(default)".to_string(),
            simple_slice.to_string(),
        )
    } else {
        let pkg_normalized = pkg_slice.replace('/', ".");
        let full_name = format!("{}.{}", pkg_normalized, simple_slice);
        (full_name, pkg_normalized, simple_slice.to_string())
    }
}

pub fn build_package_tree<'a>(classes: &'a [DexClassDefFull<'a>]) -> Vec<PackageTreeNode<'a>> {
    if classes.is_empty() {
        return Vec::new();
    }

    let mut nodes: Vec<PackageTreeNode<'a>> = Vec::new();
    let mut pkg_map: HashMap<&'a str, usize> = HashMap::new();

    for (cls_idx, cls) in classes.iter().enumerate() {
        let (pkg, _) = extract_package_and_simple_name(cls.descriptor.as_ref());
        let node_idx = if let Some(&idx) = pkg_map.get(pkg) {
            idx
        } else {
            let idx = nodes.len();
            pkg_map.insert(pkg, idx);
            let display_label = if pkg.is_empty() {
                "(default)"
            } else {
                pkg.rsplit('/').next().unwrap_or(pkg)
            };
            nodes.push(PackageTreeNode {
                package_name: if pkg.is_empty() { "(default)" } else { pkg },
                display_label,
                depth: if pkg.is_empty() {
                    0
                } else {
                    pkg.split('/').count() as u16
                },
                parent_idx: u32::MAX,
                direct_classes: Vec::new(),
                total_subtree_classes: 0,
                total_bytecode_methods: 0,
                children: Vec::new(),
            });
            idx
        };

        nodes[node_idx].direct_classes.push(cls_idx as u32);
        let bytecode_methods = cls.direct_methods.iter().filter(|m| m.code.is_some()).count()
            + cls.virtual_methods.iter().filter(|m| m.code.is_some()).count();
        nodes[node_idx].total_bytecode_methods += bytecode_methods as u32;
    }

    for node in &mut nodes {
        node.total_subtree_classes = node.direct_classes.len() as u32;
    }

    nodes
}

struct StringPool<'a> {
    entries: Vec<Cow<'a, str>>,
    index_map: HashMap<Cow<'a, str>, u32>,
}

impl<'a> StringPool<'a> {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            index_map: HashMap::new(),
        }
    }

    fn intern(&mut self, s: Cow<'a, str>) -> u32 {
        if let Some(&idx) = self.index_map.get(&s) {
            idx
        } else {
            let idx = self.entries.len() as u32;
            self.index_map.insert(s.clone(), idx);
            self.entries.push(s);
            idx
        }
    }

    #[inline]
    fn intern_cow(&mut self, s: Cow<'a, str>) -> u32 {
        self.intern(s)
    }

    #[inline]
    fn intern_owned(&mut self, s: String) -> u32 {
        self.intern(Cow::Owned(s))
    }
}

struct BufferWriter {
    buf: Vec<u8>,
}

impl BufferWriter {
    fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    #[inline]
    fn write_u8(&mut self, val: u8) {
        self.buf.push(val);
    }

    #[inline]
    fn write_u16(&mut self, val: u16) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    fn write_u32(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    fn write_i32(&mut self, val: i32) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    #[inline]
    fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    #[inline]
    fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    fn patch_u32(&mut self, offset: usize, val: u32) {
        let bytes = val.to_le_bytes();
        self.buf[offset..offset + 4].copy_from_slice(&bytes);
    }

    #[inline]
    fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dex_parser::{BuiltClass, BuiltCode, BuiltField, BuiltMethod, DexBuilder};

    fn build_synthetic_dex_fixture() -> Vec<u8> {
        let mut dex_bytes = vec![0u8; 512];
        dex_bytes[0..8].copy_from_slice(b"dex\n035\0");
        dex_bytes[0x28..0x2C].copy_from_slice(&0x12345678u32.to_le_bytes());
        dex_bytes[0x20..0x24].copy_from_slice(&512u32.to_le_bytes());

        let string_count = 7u32;
        dex_bytes[0x38..0x3C].copy_from_slice(&string_count.to_le_bytes());
        dex_bytes[0x3C..0x40].copy_from_slice(&0x70u32.to_le_bytes());

        let mut str_data_off = 0x90usize;
        let strings = [
            "Lcom/example/TestClass;",
            "Ljava/lang/Object;",
            "Ljava/lang/Runnable;",
            "TestClass.java",
            "myField",
            "testMethod",
            "V",
        ];

        for (i, s) in strings.iter().enumerate() {
            let offset_pos = 0x70 + i * 4;
            dex_bytes[offset_pos..offset_pos + 4]
                .copy_from_slice(&(str_data_off as u32).to_le_bytes());
            dex_bytes[str_data_off] = s.len() as u8;
            str_data_off += 1;
            dex_bytes[str_data_off..str_data_off + s.len()].copy_from_slice(s.as_bytes());
            str_data_off += s.len();
            dex_bytes[str_data_off] = 0;
            str_data_off += 1;
        }

        if str_data_off % 4 != 0 {
            str_data_off += 4 - (str_data_off % 4);
        }

        let type_ids_off = str_data_off as u32;
        let type_count = 4u32;
        dex_bytes[0x40..0x44].copy_from_slice(&type_count.to_le_bytes());
        dex_bytes[0x44..0x48].copy_from_slice(&type_ids_off.to_le_bytes());

        for (i, &s_idx) in [0u32, 1, 2, 6].iter().enumerate() {
            let pos = type_ids_off as usize + i * 4;
            dex_bytes[pos..pos + 4].copy_from_slice(&s_idx.to_le_bytes());
        }
        str_data_off += type_count as usize * 4;

        let proto_ids_off = str_data_off as u32;
        dex_bytes[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes());
        dex_bytes[0x4C..0x50].copy_from_slice(&proto_ids_off.to_le_bytes());
        let p_pos = proto_ids_off as usize;
        dex_bytes[p_pos..p_pos + 4].copy_from_slice(&6u32.to_le_bytes());
        dex_bytes[p_pos + 4..p_pos + 8].copy_from_slice(&3u32.to_le_bytes());
        dex_bytes[p_pos + 8..p_pos + 12].copy_from_slice(&0u32.to_le_bytes());
        str_data_off += 12;

        let field_ids_off = str_data_off as u32;
        dex_bytes[0x50..0x54].copy_from_slice(&1u32.to_le_bytes());
        dex_bytes[0x54..0x58].copy_from_slice(&field_ids_off.to_le_bytes());
        let f_pos = field_ids_off as usize;
        dex_bytes[f_pos..f_pos + 2].copy_from_slice(&0u16.to_le_bytes());
        dex_bytes[f_pos + 2..f_pos + 4].copy_from_slice(&3u16.to_le_bytes());
        dex_bytes[f_pos + 4..f_pos + 8].copy_from_slice(&4u32.to_le_bytes());
        str_data_off += 8;

        let method_ids_off = str_data_off as u32;
        dex_bytes[0x58..0x5C].copy_from_slice(&1u32.to_le_bytes());
        dex_bytes[0x5C..0x60].copy_from_slice(&method_ids_off.to_le_bytes());
        let m_pos = method_ids_off as usize;
        dex_bytes[m_pos..m_pos + 2].copy_from_slice(&0u16.to_le_bytes());
        dex_bytes[m_pos + 2..m_pos + 4].copy_from_slice(&0u16.to_le_bytes());
        dex_bytes[m_pos + 4..m_pos + 8].copy_from_slice(&5u32.to_le_bytes());
        str_data_off += 8;

        let iface_list_off = str_data_off as u32;
        dex_bytes[str_data_off..str_data_off + 4].copy_from_slice(&1u32.to_le_bytes());
        dex_bytes[str_data_off + 4..str_data_off + 6].copy_from_slice(&2u16.to_le_bytes());
        str_data_off += 8;

        let code_item_off = str_data_off as u32;
        dex_bytes[str_data_off..str_data_off + 2].copy_from_slice(&4u16.to_le_bytes());
        dex_bytes[str_data_off + 2..str_data_off + 4].copy_from_slice(&1u16.to_le_bytes());
        dex_bytes[str_data_off + 4..str_data_off + 6].copy_from_slice(&2u16.to_le_bytes());
        dex_bytes[str_data_off + 6..str_data_off + 8].copy_from_slice(&0u16.to_le_bytes());
        dex_bytes[str_data_off + 8..str_data_off + 12].copy_from_slice(&0u32.to_le_bytes());
        dex_bytes[str_data_off + 12..str_data_off + 16].copy_from_slice(&3u32.to_le_bytes());
        dex_bytes[str_data_off + 16..str_data_off + 22]
            .copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x0e, 0x00]);
        str_data_off += 24;

        let class_data_off = str_data_off as u32;
        dex_bytes[str_data_off] = 0;
        dex_bytes[str_data_off + 1] = 1;
        dex_bytes[str_data_off + 2] = 1;
        dex_bytes[str_data_off + 3] = 0;
        str_data_off += 4;
        dex_bytes[str_data_off] = 0;
        dex_bytes[str_data_off + 1] = 1;
        str_data_off += 2;
        dex_bytes[str_data_off] = 0;
        dex_bytes[str_data_off + 1] = 1;
        let mut val = code_item_off;
        while val >= 0x80 {
            dex_bytes[str_data_off + 2] = ((val & 0x7F) | 0x80) as u8;
            val >>= 7;
            str_data_off += 1;
        }
        dex_bytes[str_data_off + 2] = (val & 0x7F) as u8;
        str_data_off += 3;

        if str_data_off % 4 != 0 {
            str_data_off += 4 - (str_data_off % 4);
        }
        let class_defs_off = str_data_off as u32;
        dex_bytes[0x60..0x64].copy_from_slice(&1u32.to_le_bytes());
        dex_bytes[0x64..0x68].copy_from_slice(&class_defs_off.to_le_bytes());

        let c_pos = class_defs_off as usize;
        dex_bytes[c_pos..c_pos + 4].copy_from_slice(&0u32.to_le_bytes());
        dex_bytes[c_pos + 4..c_pos + 8].copy_from_slice(&1u32.to_le_bytes());
        dex_bytes[c_pos + 8..c_pos + 12].copy_from_slice(&1u32.to_le_bytes());
        dex_bytes[c_pos + 12..c_pos + 16].copy_from_slice(&iface_list_off.to_le_bytes());
        dex_bytes[c_pos + 16..c_pos + 20].copy_from_slice(&3u32.to_le_bytes());
        dex_bytes[c_pos + 20..c_pos + 24].copy_from_slice(&0u32.to_le_bytes());
        dex_bytes[c_pos + 24..c_pos + 28].copy_from_slice(&class_data_off.to_le_bytes());
        dex_bytes[c_pos + 28..c_pos + 32].copy_from_slice(&0u32.to_le_bytes());

        dex_bytes
    }

    #[test]
    fn test_extract_package_and_simple_name() {
        assert_eq!(
            extract_package_and_simple_name("Lcom/example/MyClass;"),
            ("com/example", "MyClass")
        );
        assert_eq!(
            extract_package_and_simple_name("LMainActivity;"),
            ("", "MainActivity")
        );
        assert_eq!(
            extract_package_and_simple_name("Lfoo/bar/Outer$Inner;"),
            ("foo/bar", "Outer$Inner")
        );
    }

    #[test]
    fn test_parse_class_descriptor() {
        let (full, pkg, simple) = parse_class_descriptor("Lcom/example/MyClass;");
        assert_eq!(full, "com.example.MyClass");
        assert_eq!(pkg, "com.example");
        assert_eq!(simple, "MyClass");

        let (full_def, pkg_def, simple_def) = parse_class_descriptor("LMainActivity;");
        assert_eq!(full_def, "MainActivity");
        assert_eq!(pkg_def, "(default)");
        assert_eq!(simple_def, "MainActivity");
    }

    #[test]
    fn test_package_tree_grouping() {
        let classes = vec![
            DexClassDefFull {
                class_def_idx: 0,
                class_idx: 0,
                access_flags: 1,
                descriptor: Cow::Borrowed("Lcom/example/A;"),
                superclass: None,
                source_file: None,
                interfaces: Vec::new(),
                static_fields: Vec::new(),
                instance_fields: Vec::new(),
                direct_methods: Vec::new(),
                virtual_methods: Vec::new(),
                annotations_off: 0,
                static_values_off: 0,
                class_data_off: 0,
            },
            DexClassDefFull {
                class_def_idx: 1,
                class_idx: 1,
                access_flags: 1,
                descriptor: Cow::Borrowed("Lcom/example/B;"),
                superclass: None,
                source_file: None,
                interfaces: Vec::new(),
                static_fields: Vec::new(),
                instance_fields: Vec::new(),
                direct_methods: Vec::new(),
                virtual_methods: Vec::new(),
                annotations_off: 0,
                static_values_off: 0,
                class_data_off: 0,
            },
            DexClassDefFull {
                class_def_idx: 2,
                class_idx: 2,
                access_flags: 1,
                descriptor: Cow::Borrowed("LRootClass;"),
                superclass: None,
                source_file: None,
                interfaces: Vec::new(),
                static_fields: Vec::new(),
                instance_fields: Vec::new(),
                direct_methods: Vec::new(),
                virtual_methods: Vec::new(),
                annotations_off: 0,
                static_values_off: 0,
                class_data_off: 0,
            },
        ];

        let tree = build_package_tree(&classes);
        assert_eq!(tree.len(), 2);

        let com_pkg = tree.iter().find(|n| n.package_name == "com/example").unwrap();
        assert_eq!(com_pkg.direct_classes, vec![0, 1]);
        assert_eq!(com_pkg.total_subtree_classes, 2);

        let def_pkg = tree.iter().find(|n| n.package_name == "(default)").unwrap();
        assert_eq!(def_pkg.direct_classes, vec![2]);
        assert_eq!(def_pkg.total_subtree_classes, 1);
    }

    #[test]
    fn test_synthetic_dex_parse_and_pack_roundtrip() {
        let dex_bytes = build_synthetic_dex_fixture();
        let dex = DexFile::parse(&dex_bytes).expect("Failed to parse synthetic DEX");
        assert_eq!(dex.class_def_count(), 1);
        assert_eq!(dex.string_count(), 7);

        let cls = dex.get_class_def_full(0).expect("Failed to get class def");
        assert_eq!(cls.descriptor.as_ref(), "Lcom/example/TestClass;");
        assert_eq!(cls.superclass.as_deref(), Some("Ljava/lang/Object;"));
        assert_eq!(cls.source_file.as_deref(), Some("TestClass.java"));
        assert_eq!(cls.interfaces.len(), 1);
        assert_eq!(cls.interfaces[0].as_ref(), "Ljava/lang/Runnable;");
        assert_eq!(cls.instance_fields.len(), 1);
        assert_eq!(cls.instance_fields[0].name.as_ref(), "myField");
        assert_eq!(cls.direct_methods.len(), 1);

        let m = &cls.direct_methods[0];
        assert_eq!(m.name.as_ref(), "testMethod");
        let code = m.code.expect("code meta present");
        assert_eq!(code.registers_size, 4);
        assert_eq!(code.ins_size, 1);
        assert_eq!(code.outs_size, 2);
        assert_eq!(code.insns_count, 3);

        // Golden D2CN v1 wire layout parity check
        let packed = pack_dex_classes(&dex);
        assert!(packed.len() >= 32);

        let magic = u32::from_le_bytes([packed[0], packed[1], packed[2], packed[3]]);
        assert_eq!(magic, 0x4E433244); // 'D','2','C','N'
        let version = u16::from_le_bytes([packed[4], packed[5]]);
        assert_eq!(version, 1);
        let flags = u16::from_le_bytes([packed[6], packed[7]]);
        assert_eq!(flags, 0);
        let header_size = u32::from_le_bytes([packed[8], packed[9], packed[10], packed[11]]);
        assert_eq!(header_size, 32);
        let string_count = u32::from_le_bytes([packed[12], packed[13], packed[14], packed[15]]);
        assert_eq!(string_count, 10);
        let class_count = u32::from_le_bytes([packed[16], packed[17], packed[18], packed[19]]);
        assert_eq!(class_count, 1);
        let method_count = u32::from_le_bytes([packed[20], packed[21], packed[22], packed[23]]);
        assert_eq!(method_count, 1);
        let string_pool_off = u32::from_le_bytes([packed[24], packed[25], packed[26], packed[27]]);
        assert_eq!(string_pool_off, 32);
        let classes_off = u32::from_le_bytes([packed[28], packed[29], packed[30], packed[31]]);

        // Decode string pool sequentially and verify exact interning order matches baseline D2CN v1
        let mut cursor = string_pool_off as usize;
        let mut decoded_pool = Vec::with_capacity(string_count as usize);
        for _ in 0..string_count {
            let slen = u16::from_le_bytes([packed[cursor], packed[cursor + 1]]) as usize;
            cursor += 2;
            decoded_pool.push(std::str::from_utf8(&packed[cursor..cursor + slen]).unwrap().to_string());
            cursor += slen;
        }
        assert_eq!(cursor as u32, classes_off);
        assert_eq!(
            decoded_pool,
            vec![
                "Lcom/example/TestClass;",
                "com.example.TestClass",
                "com.example",
                "TestClass",
                "Ljava/lang/Object;",
                "TestClass.java",
                "Ljava/lang/Runnable;",
                "myField",
                "V",
                "testMethod",
            ]
        );
    }

    #[test]
    fn test_d2cn_roundtrips_mutf8_surrogate_pair_class_and_method() {
        let mut b = DexBuilder::new();
        b.add_class(BuiltClass {
            descriptor: "Lcom/example/Emoji😀;".into(),
            access_flags: 1,
            superclass: Some("Ljava/lang/Object;".into()),
            interfaces: vec![],
            source_file: Some("Emoji😀.java".into()),
            static_fields: vec![],
            instance_fields: vec![BuiltField {
                class: "Lcom/example/Emoji😀;".into(),
                name: "flag🚀".into(),
                typ: "I".into(),
                access_flags: 1,
                static_field: false,
                static_value: None,
            }],
            direct_methods: vec![BuiltMethod {
                class: "Lcom/example/Emoji😀;".into(),
                name: "run𐐷".into(),
                proto: "()V".into(),
                access_flags: 1,
                direct: true,
                code: Some(BuiltCode {
                    registers_size: 1,
                    ins_size: 0,
                    outs_size: 0,
                    insns: vec![0x0e, 0x00],
                    tries: vec![],
                    debug_info_off: 0,
                    debug_ops: vec![],
                }),
            }],
            virtual_methods: vec![],
            annotations: Default::default(),
        });
        let raw = b.finish().expect("builder should emit valid DEX");
        let dex = DexFile::parse(&raw).expect("parse builder output");
        let packed = pack_dex_classes(&dex);
        let packed_str = String::from_utf8_lossy(&packed);
        assert!(packed_str.contains("com.example.Emoji😀"));
        assert!(packed_str.contains("Emoji😀.java"));
        assert!(packed_str.contains("flag🚀"));
        assert!(packed_str.contains("run𐐷"));
    }
}
