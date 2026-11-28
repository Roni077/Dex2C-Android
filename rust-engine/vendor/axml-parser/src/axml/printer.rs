//! AXMLPrinter - converts binary AXML to XML bytes.

use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use std::collections::HashMap;
use std::io::Cursor;

use crate::axml::parser::AXMLParser;
use crate::constants::*;
use crate::formatters::format_value;

const NS_ANDROID_URI: &str = "http://schemas.android.com/apk/res/android";

/// Converts AXML binary to XML.
pub struct AXMLPrinter {
    parser: AXMLParser,
    pub packerwarning: bool,
    xml_bytes: Vec<u8>,
    root_tag: Option<String>,
}

impl AXMLPrinter {
    pub fn new(raw_buff: &[u8]) -> Self {
        let mut parser = AXMLParser::new(raw_buff);
        let mut packerwarning = false;
        let mut stack: Vec<String> = Vec::new();
        let mut writer = Writer::new(Cursor::new(Vec::new()));

        let _ = writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)));

        let mut root_tag = None;
        while parser.is_valid() {
            let event_type = parser.next();

            match event_type {
                START_TAG => {
                    let name = parser.name();
                    if name.is_empty() {
                        continue;
                    }
                    let uri = parser.namespace();
                    let (prefix_uri, tag_name) = Self::fix_name(&mut parser, &uri, &name);
                    let tag = if prefix_uri.is_empty() {
                        tag_name.clone()
                    } else {
                        format!("{}{}", prefix_uri, tag_name)
                    };

                    if let Some(comment) = parser.comment() {
                        use quick_xml::events::BytesText;
                        let _ = writer
                            .write_event(Event::Comment(BytesText::from_escaped(comment.as_str())));
                    }

                    let nsmap = parser.nsmap();
                    let mut attrs: Vec<(String, String)> = Vec::new();
                    for (prefix, uri) in &nsmap {
                        attrs.push((format!("xmlns:{}", prefix), uri.clone()));
                    }

                    for i in 0..parser.get_attribute_count() {
                        if i < 0 {
                            break;
                        }
                        let i = i as usize;
                        let attr_ns = parser.get_attribute_namespace(i);
                        let aname = parser.get_attribute_name(i);
                        let (_, attr_name) = Self::fix_name(&mut parser, &attr_ns, &aname);
                        let value =
                            Self::fix_value_static(&Self::get_attribute_value(&mut parser, i));
                        let key = Self::format_attr_key(&nsmap, &attr_ns, &attr_name);
                        attrs.push((key, value));
                    }

                    let mut elem = BytesStart::new(tag.as_str());
                    for (k, v) in &attrs {
                        elem.push_attribute((k.as_str(), v.as_str()));
                    }
                    let _ = writer.write_event(Event::Start(elem));

                    stack.push(tag.clone());
                    if root_tag.is_none() {
                        root_tag = Some(tag);
                    }
                }
                END_TAG => {
                    let name = parser.name();
                    if let Some(tag) = stack.pop() {
                        if !name.is_empty() {
                            let _ = writer.write_event(Event::End(BytesEnd::new(tag.as_str())));
                        }
                    }
                }
                TEXT => {
                    let text = parser.text();
                    if !text.is_empty() {
                        use quick_xml::events::BytesText;
                        writer
                            .write_event(Event::Text(BytesText::new(text.as_str())))
                            .ok();
                    }
                }
                END_DOCUMENT => break,
                _ => {}
            }
        }

        packerwarning = packerwarning || parser.packerwarning;

        let xml_bytes = writer.into_inner().into_inner();
        let root_tag = stack.first().cloned();

        AXMLPrinter {
            parser,
            packerwarning,
            xml_bytes,
            root_tag,
        }
    }

    fn print_namespace(uri: &str) -> String {
        if uri.is_empty() {
            String::new()
        } else {
            format!("{{{}}}", uri)
        }
    }

    /// Prefer `android:name` over Clark `{http://…}name` so re-encode works.
    fn format_attr_key(nsmap: &HashMap<String, String>, attr_ns: &str, attr_name: &str) -> String {
        if attr_ns.is_empty() {
            return attr_name.to_string();
        }
        for (prefix, uri) in nsmap {
            if uri == attr_ns && !prefix.is_empty() {
                return format!("{prefix}:{attr_name}");
            }
        }
        if attr_ns == NS_ANDROID_URI {
            return format!("android:{attr_name}");
        }
        // Fallback Clark notation (rare non-android namespaces without xmlns).
        format!("{{{attr_ns}}}{attr_name}")
    }

    fn fix_name(parser: &mut AXMLParser, prefix: &str, name: &str) -> (String, String) {
        let mut name = name.to_string();
        let mut prefix = prefix.to_string();

        if !name.is_empty()
            && !name.chars().next().unwrap_or('a').is_alphabetic()
            && name.chars().next() != Some('_')
        {
            parser.packerwarning = true;
            name = format!("_{}", name);
        }

        let nsmap = parser.nsmap();
        if name.starts_with("android:") && prefix.is_empty() && nsmap.contains_key("android") {
            prefix = Self::print_namespace(nsmap.get("android").unwrap());
            name = name.strip_prefix("android:").unwrap_or(&name).to_string();
            parser.packerwarning = true;
        } else if name.contains(':') && prefix.is_empty() {
            let parts: Vec<&str> = name.splitn(2, ':').collect();
            if parts.len() == 2 {
                let embedded_prefix = parts[0];
                let new_name = parts[1];
                if nsmap.contains_key(embedded_prefix) {
                    prefix = Self::print_namespace(nsmap.get(embedded_prefix).unwrap());
                    name = new_name.to_string();
                } else {
                    parser.packerwarning = true;
                    name = name.replace(':', "_");
                }
            }
        }

        let valid_name: String = name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '.' || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if valid_name != name {
            parser.packerwarning = true;
            name = valid_name;
        }

        (prefix, name)
    }

    /// Public for tests - fix value per XML charset rules.
    pub fn fix_value_static(value: &str) -> String {
        let mut value = value.to_string();
        if let Some(pos) = value.find('\0') {
            value = value[..pos].to_string();
        }
        let valid_chars = |c: char| {
            matches!(c,
                '\u{0020}'..='\u{D7FF}' | '\u{0009}' | '\u{000A}' | '\u{000D}'
                | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
        };
        if !value.chars().all(valid_chars) {
            value = value
                .chars()
                .map(|c| if valid_chars(c) { c } else { '_' })
                .collect();
        }
        value
    }

    fn get_attribute_value(parser: &mut AXMLParser, index: usize) -> String {
        let value_type = parser.get_attribute_value_type(index);
        let value_data = parser.get_attribute_value_data(index);
        let p = parser;
        format_value(value_type, value_data, |idx: u32| p.get_string_at(idx))
    }

    pub fn get_xml(&self, pretty: bool) -> Vec<u8> {
        if pretty {
            self.xml_bytes.clone()
        } else {
            self.xml_bytes.clone()
        }
    }

    pub fn get_buff(&self) -> Vec<u8> {
        self.get_xml(false)
    }

    pub fn is_valid(&self) -> bool {
        self.parser.is_valid()
    }

    pub fn is_packed(&self) -> bool {
        self.packerwarning || self.parser.packerwarning
    }

    pub fn package(&self) -> String {
        self.get_attribute_value_from_manifest("manifest", "package")
    }

    pub fn androidversion(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(
            "Code".to_string(),
            self.get_attribute_value_from_manifest("manifest", "versionCode"),
        );
        m.insert(
            "Name".to_string(),
            self.get_attribute_value_from_manifest("manifest", "versionName"),
        );
        m
    }

    fn get_attribute_value_from_manifest(&self, tag_name: &str, attribute: &str) -> String {
        let xml_str = String::from_utf8_lossy(&self.xml_bytes);
        let _android_ns = format!("{{{}}}", NS_ANDROID_URI);
        let needle_android = format!("{}=\"", attribute);
        let needle_plain = format!("{}=\"", attribute);
        for line in xml_str.lines() {
            if line.contains(&format!("<{}", tag_name)) || line.contains("manifest") {
                if let Some(start) = line.find(&needle_android) {
                    let start = start + needle_android.len();
                    if let Some(end) = line[start..].find('"') {
                        return line[start..start + end].to_string();
                    }
                }
                if let Some(start) = line.find(&needle_plain) {
                    let start = start + needle_plain.len();
                    if let Some(end) = line[start..].find('"') {
                        return line[start..start + end].to_string();
                    }
                }
            }
        }
        String::new()
    }

    pub fn permissions(&self) -> Vec<String> {
        let mut perms = std::collections::HashSet::new();
        let xml_str = String::from_utf8_lossy(&self.xml_bytes);
        let mut pos = 0;
        while let Some(idx) = xml_str[pos..].find("uses-permission") {
            let segment_start = pos + idx + "uses-permission".len();
            if let Some(name_attr) = xml_str[segment_start..].find("name=\"") {
                let name_start = segment_start + name_attr + 6;
                if let Some(name_end) = xml_str[name_start..].find('"') {
                    let name = xml_str[name_start..name_start + name_end].to_string();
                    perms.insert(name);
                }
            }
            pos = pos + idx + 1;
        }
        perms.into_iter().collect()
    }

    pub fn uses_permissions(&self) -> Vec<[Option<String>; 2]> {
        let mut result = Vec::new();
        let xml_str = String::from_utf8_lossy(&self.xml_bytes);
        for line in xml_str.lines() {
            if line.contains("uses-permission") {
                let mut name = None;
                let mut max_sdk = None;
                if let Some(start) = line.find("name=\"") {
                    let start = start + 6;
                    if let Some(end) = line[start..].find('"') {
                        name = Some(line[start..start + end].to_string());
                    }
                }
                if let Some(start) = line.find("maxSdkVersion=\"") {
                    let start = start + 14;
                    if let Some(end) = line[start..].find('"') {
                        max_sdk = Some(line[start..start + end].to_string());
                    }
                }
                result.push([name, max_sdk]);
            }
        }
        result
    }

    pub fn get_xml_obj_tag(&self) -> Option<String> {
        self.root_tag.clone()
    }
}
