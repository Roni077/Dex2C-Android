//! Encode text XML into Android binary AXML.

use std::collections::HashMap;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::constants::*;
use crate::error::ResParserError;
use crate::public::{attr_name_to_id, ANDROID_NS_URI};

const NO_INDEX: i32 = -1;

/// Encode UTF-8 XML text into binary AXML bytes.
pub fn encode_xml(xml: &[u8]) -> Result<Vec<u8>, ResParserError> {
    let tree = parse_xml_tree(xml)?;
    encode_tree(&tree)
}

#[derive(Debug, Clone)]
struct XmlAttr {
    ns_uri: Option<String>,
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
enum XmlNode {
    Element {
        ns_uri: Option<String>,
        name: String,
        attrs: Vec<XmlAttr>,
        children: Vec<XmlNode>,
        namespaces: Vec<(String, String)>,
    },
    Text(String),
}

fn parse_xml_tree(xml: &[u8]) -> Result<XmlNode, ResParserError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    struct Frame {
        name: String,
        ns_uri: Option<String>,
        attrs: Vec<XmlAttr>,
        namespaces: Vec<(String, String)>,
        children: Vec<XmlNode>,
    }

    let mut stack: Vec<Frame> = Vec::new();
    let mut ns_stack: Vec<Vec<(String, String)>> = Vec::new();
    let mut root: Option<XmlNode> = None;

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| ResParserError(format!("XML parse error: {e}")))?;
        match event {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let is_empty = matches!(event, Event::Empty(_));
                let qname = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                let (prefix, local) = split_qname(&qname);
                let mut declared = Vec::new();
                let mut attrs = Vec::new();
                for a in e.attributes().flatten() {
                    let key = String::from_utf8_lossy(a.key.as_ref()).into_owned();
                    let val = a
                        .unescape_value()
                        .map(|v| v.into_owned())
                        .unwrap_or_default();
                    if key == "xmlns" {
                        declared.push((String::new(), val));
                    } else if let Some(p) = key.strip_prefix("xmlns:") {
                        declared.push((p.to_string(), val));
                    } else {
                        let (ap, an) = split_qname(&key);
                        let ns_uri = resolve_prefix(ap.as_deref(), &ns_stack, &declared);
                        attrs.push(XmlAttr {
                            ns_uri,
                            name: an,
                            value: val,
                        });
                    }
                }
                let ns_uri = resolve_prefix(prefix.as_deref(), &ns_stack, &declared);
                if is_empty {
                    let node = XmlNode::Element {
                        ns_uri,
                        name: local,
                        attrs,
                        children: Vec::new(),
                        namespaces: declared,
                    };
                    if let Some(frame) = stack.last_mut() {
                        frame.children.push(node);
                    } else {
                        root = Some(node);
                    }
                } else {
                    ns_stack.push(declared.clone());
                    stack.push(Frame {
                        name: local,
                        ns_uri,
                        attrs,
                        namespaces: declared,
                        children: Vec::new(),
                    });
                }
            }
            Event::End(_) => {
                let frame = stack
                    .pop()
                    .ok_or_else(|| ResParserError("unbalanced XML end tag".into()))?;
                ns_stack.pop();
                let node = XmlNode::Element {
                    ns_uri: frame.ns_uri,
                    name: frame.name,
                    attrs: frame.attrs,
                    children: frame.children,
                    namespaces: frame.namespaces,
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    root = Some(node);
                }
            }
            Event::Text(t) => {
                let text = t.unescape().unwrap_or_default().into_owned();
                if !text.trim().is_empty() {
                    if let Some(frame) = stack.last_mut() {
                        frame.children.push(XmlNode::Text(text));
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    root.ok_or_else(|| ResParserError("XML has no root element".into()))
}

fn split_qname(qname: &str) -> (Option<String>, String) {
    if let Some((p, n)) = qname.split_once(':') {
        (Some(p.to_string()), n.to_string())
    } else {
        (None, qname.to_string())
    }
}

fn resolve_prefix(
    prefix: Option<&str>,
    ns_stack: &[Vec<(String, String)>],
    declared: &[(String, String)],
) -> Option<String> {
    let Some(prefix) = prefix else {
        return None;
    };
    for (p, uri) in declared.iter().rev() {
        if p == prefix {
            return Some(uri.clone());
        }
    }
    for frame in ns_stack.iter().rev() {
        for (p, uri) in frame.iter().rev() {
            if p == prefix {
                return Some(uri.clone());
            }
        }
    }
    if prefix == "android" {
        return Some(ANDROID_NS_URI.to_string());
    }
    None
}

#[derive(Default)]
struct StringPool {
    strings: Vec<String>,
    index: HashMap<String, u32>,
}

impl StringPool {
    fn add(&mut self, s: &str) -> u32 {
        if let Some(&i) = self.index.get(s) {
            return i;
        }
        let i = self.strings.len() as u32;
        self.strings.push(s.to_string());
        self.index.insert(s.to_string(), i);
        i
    }

    fn id(&self, s: &str) -> i32 {
        self.index
            .get(s)
            .copied()
            .map(|v| v as i32)
            .unwrap_or(NO_INDEX)
    }
}

fn collect_strings(node: &XmlNode, pool: &mut StringPool) {
    match node {
        XmlNode::Element {
            ns_uri,
            name,
            attrs,
            children,
            namespaces,
        } => {
            for (prefix, uri) in namespaces {
                if !prefix.is_empty() {
                    pool.add(prefix);
                }
                pool.add(uri);
            }
            if let Some(ns) = ns_uri {
                pool.add(ns);
            }
            pool.add(name);
            for a in attrs {
                if let Some(ns) = &a.ns_uri {
                    pool.add(ns);
                }
                pool.add(&a.name);
                pool.add(&a.value);
            }
            for c in children {
                collect_strings(c, pool);
            }
        }
        XmlNode::Text(t) => {
            pool.add(t);
        }
    }
}

fn encode_tree(root: &XmlNode) -> Result<Vec<u8>, ResParserError> {
    let mut pool = StringPool::default();
    collect_strings(root, &mut pool);

    let mut resource_ids = vec![0u32; pool.strings.len()];
    for (idx, s) in pool.strings.iter().enumerate() {
        if let Some(id) = attr_name_to_id(s) {
            resource_ids[idx] = id;
        }
    }
    // Trim trailing zeros from resource map but keep at least indices that have ids.
    while resource_ids.last().copied() == Some(0) && !resource_ids.is_empty() {
        // Keep map covering highest attr string index with a non-zero id.
        let last_nonzero = resource_ids.iter().rposition(|&x| x != 0);
        if let Some(i) = last_nonzero {
            resource_ids.truncate(i + 1);
            break;
        } else {
            resource_ids.clear();
            break;
        }
    }

    let mut chunks_after_pools = Vec::new();
    if let XmlNode::Element { namespaces, .. } = root {
        for (prefix, uri) in namespaces {
            write_namespace_chunk(
                &mut chunks_after_pools,
                RES_XML_START_NAMESPACE_TYPE,
                if prefix.is_empty() {
                    NO_INDEX
                } else {
                    pool.id(prefix)
                },
                pool.id(uri),
            );
        }
    }
    write_node(&mut chunks_after_pools, root, &pool)?;
    if let XmlNode::Element { namespaces, .. } = root {
        for (prefix, uri) in namespaces.iter().rev() {
            write_namespace_chunk(
                &mut chunks_after_pools,
                RES_XML_END_NAMESPACE_TYPE,
                if prefix.is_empty() {
                    NO_INDEX
                } else {
                    pool.id(prefix)
                },
                pool.id(uri),
            );
        }
    }

    let string_pool = write_string_pool_utf16(&pool.strings);
    let res_map = write_resource_map(&resource_ids);
    let content_size = string_pool.len() + res_map.len() + chunks_after_pools.len();
    let file_size = 8 + content_size;

    let mut body = Vec::with_capacity(file_size);
    body.extend_from_slice(&RES_XML_TYPE.to_le_bytes());
    body.extend_from_slice(&8u16.to_le_bytes());
    body.extend_from_slice(&(file_size as u32).to_le_bytes());
    body.extend_from_slice(&string_pool);
    body.extend_from_slice(&res_map);
    body.extend_from_slice(&chunks_after_pools);
    Ok(body)
}

fn write_string_pool_utf16(strings: &[String]) -> Vec<u8> {
    let count = strings.len() as u32;
    let mut offsets = Vec::with_capacity(strings.len());
    let mut data = Vec::new();
    for s in strings {
        offsets.push(data.len() as u32);
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let len = utf16.len() as u16;
        data.extend_from_slice(&len.to_le_bytes());
        for c in utf16 {
            data.extend_from_slice(&c.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }

    let header_size: u16 = 0x1C;
    let strings_start = header_size as u32 + count * 4;
    let chunk_size = strings_start + data.len() as u32;

    let mut out = Vec::new();
    out.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&chunk_size.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&strings_start.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for off in offsets {
        out.extend_from_slice(&off.to_le_bytes());
    }
    out.extend_from_slice(&data);
    out
}

fn write_resource_map(ids: &[u32]) -> Vec<u8> {
    let header_size: u16 = 8;
    let chunk_size = header_size as u32 + (ids.len() as u32) * 4;
    let mut out = Vec::new();
    out.extend_from_slice(&RES_XML_RESOURCE_MAP_TYPE.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&chunk_size.to_le_bytes());
    for id in ids {
        out.extend_from_slice(&id.to_le_bytes());
    }
    out
}

fn write_namespace_chunk(out: &mut Vec<u8>, chunk_type: u16, prefix: i32, uri: i32) {
    let header_size: u16 = 0x10;
    let chunk_size: u32 = 0x18;
    out.extend_from_slice(&chunk_type.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&chunk_size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    out.extend_from_slice(&(prefix as u32).to_le_bytes());
    out.extend_from_slice(&(uri as u32).to_le_bytes());
}

fn write_node(out: &mut Vec<u8>, node: &XmlNode, pool: &StringPool) -> Result<(), ResParserError> {
    match node {
        XmlNode::Element {
            ns_uri,
            name,
            attrs,
            children,
            ..
        } => {
            write_start_element(out, ns_uri.as_deref(), name, attrs, pool);
            for c in children {
                write_node(out, c, pool)?;
            }
            write_end_element(out, ns_uri.as_deref(), name, pool);
        }
        XmlNode::Text(t) => write_cdata(out, pool.id(t)),
    }
    Ok(())
}

fn write_start_element(
    out: &mut Vec<u8>,
    ns_uri: Option<&str>,
    name: &str,
    attrs: &[XmlAttr],
    pool: &StringPool,
) {
    // PackageManager binary-searches attributes by resource id. Attributes with
    // no id (0) must come first, then ascending resource ids.
    let mut attrs = attrs.to_vec();
    attrs.sort_by_key(|a| attr_name_to_id(&a.name).unwrap_or(0));
    let attrs = attrs.as_slice();
    let attr_count = attrs.len() as u16;
    let header_size: u16 = 0x10;
    let chunk_size = 0x24u32 + (attr_count as u32) * 20;

    let mut id_index = 0u16;
    let mut class_index = 0u16;
    let mut style_index = 0u16;
    for (i, a) in attrs.iter().enumerate() {
        match a.name.as_str() {
            "id" => id_index = (i as u16) + 1,
            "class" => class_index = (i as u16) + 1,
            "style" => style_index = (i as u16) + 1,
            _ => {}
        }
    }

    out.extend_from_slice(&RES_XML_START_ELEMENT_TYPE.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&chunk_size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let ns = ns_uri.map(|u| pool.id(u)).unwrap_or(NO_INDEX);
    out.extend_from_slice(&(ns as u32).to_le_bytes());
    out.extend_from_slice(&(pool.id(name) as u32).to_le_bytes());
    out.extend_from_slice(&0x14u16.to_le_bytes());
    out.extend_from_slice(&0x14u16.to_le_bytes());
    out.extend_from_slice(&attr_count.to_le_bytes());
    out.extend_from_slice(&id_index.to_le_bytes());
    out.extend_from_slice(&class_index.to_le_bytes());
    out.extend_from_slice(&style_index.to_le_bytes());

    for a in attrs {
        write_attribute(out, a, pool);
    }
}

fn write_attribute(out: &mut Vec<u8>, attr: &XmlAttr, pool: &StringPool) {
    let ns = attr
        .ns_uri
        .as_deref()
        .map(|u| pool.id(u))
        .unwrap_or(NO_INDEX);
    let name = pool.id(&attr.name);
    let (raw_value, data_type, data) = encode_attr_value(attr, pool);

    out.extend_from_slice(&(ns as u32).to_le_bytes());
    out.extend_from_slice(&(name as u32).to_le_bytes());
    out.extend_from_slice(&(raw_value as u32).to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.push(0);
    out.push(data_type);
    out.extend_from_slice(&data.to_le_bytes());
}

fn encode_attr_value(attr: &XmlAttr, pool: &StringPool) -> (i32, u8, u32) {
    let v = attr.value.as_str();
    if v == "true" {
        return (NO_INDEX, TYPE_INT_BOOLEAN, 0xFFFF_FFFF);
    }
    if v == "false" {
        return (NO_INDEX, TYPE_INT_BOOLEAN, 0);
    }
    if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        if let Ok(n) = u32::from_str_radix(hex, 16) {
            return (NO_INDEX, TYPE_INT_HEX, n);
        }
    }
    if v.starts_with('#') && (v.len() == 7 || v.len() == 9) {
        let hex = &v[1..];
        if let Ok(mut n) = u32::from_str_radix(hex, 16) {
            if hex.len() == 6 {
                n |= 0xFF00_0000;
            }
            return (NO_INDEX, TYPE_INT_COLOR_ARGB8, n);
        }
    }
    if let Some(rest) = v.strip_prefix('@') {
        let hex = rest.rsplit(':').next().unwrap_or(rest);
        if hex.len() == 8 {
            if let Ok(n) = u32::from_str_radix(hex, 16) {
                return (NO_INDEX, TYPE_REFERENCE, n);
            }
        }
    }
    // Keep known string-typed attrs as strings (e.g. compileSdkVersionCodename="14").
    if matches!(
        attr.name.as_str(),
        "versionName"
            | "compileSdkVersionCodename"
            | "name"
            | "label"
            | "value"
            | "permission"
            | "authorities"
            | "process"
            | "taskAffinity"
            | "parentActivityName"
            | "appComponentFactory"
            | "scheme"
            | "host"
            | "path"
            | "pathPrefix"
            | "pathPattern"
            | "mimeType"
            | "action"
            | "targetPackage"
            | "targetClass"
            | "sharedUserId"
            | "package"
            | "platformBuildVersionName"
    ) {
        let sid = pool.id(v);
        return (sid, TYPE_STRING, sid as u32);
    }
    if let Ok(n) = v.parse::<i32>() {
        return (NO_INDEX, TYPE_INT_DEC, n as u32);
    }
    if attr.name == "platformBuildVersionCode" {
        if let Ok(n) = v.parse::<u32>() {
            return (NO_INDEX, TYPE_INT_DEC, n);
        }
    }
    let sid = pool.id(v);
    (sid, TYPE_STRING, sid as u32)
}

fn write_end_element(out: &mut Vec<u8>, ns_uri: Option<&str>, name: &str, pool: &StringPool) {
    let header_size: u16 = 0x10;
    let chunk_size: u32 = 0x18;
    out.extend_from_slice(&RES_XML_END_ELEMENT_TYPE.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&chunk_size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let ns = ns_uri.map(|u| pool.id(u)).unwrap_or(NO_INDEX);
    out.extend_from_slice(&(ns as u32).to_le_bytes());
    out.extend_from_slice(&(pool.id(name) as u32).to_le_bytes());
}

fn write_cdata(out: &mut Vec<u8>, string_idx: i32) {
    let header_size: u16 = 0x10;
    let chunk_size: u32 = 0x1C;
    out.extend_from_slice(&RES_XML_CDATA_TYPE.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&chunk_size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    out.extend_from_slice(&(string_idx as u32).to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.push(0);
    out.push(TYPE_STRING);
    out.extend_from_slice(&(string_idx as u32).to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::axml::printer::AXMLPrinter;

    #[test]
    fn encode_simple_manifest_roundtrip() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app" android:versionCode="1" android:versionName="1.0">
    <application android:label="Hello" android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true"/>
    </application>
</manifest>
"#;
        let binary = encode_xml(xml).expect("encode");
        assert!(binary.len() > 8);
        assert_eq!(&binary[0..2], &RES_XML_TYPE.to_le_bytes());
        let printer = AXMLPrinter::new(&binary);
        assert!(printer.is_valid(), "encoded AXML must parse");
        let xml_bytes = printer.get_xml(true);
        let out = String::from_utf8_lossy(&xml_bytes);
        assert!(out.contains("manifest"));
        assert!(out.contains("com.example.app") || out.contains("package"));
    }
}
