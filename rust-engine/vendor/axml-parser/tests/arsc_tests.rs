//! ARSC parser tests - ported from androguard/axml Python test_parser_arsc.py

use axml_parser::{ARSCHeader, ARSCParser, ARSCResTableConfig};
use std::io::Cursor;
use std::path::PathBuf;

use axml_parser::ResParserError;

fn test_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

#[test]
fn test_arsc_header() {
    let mut cursor = Cursor::new(b"\x02\x01");
    let result = ARSCHeader::read(&mut cursor, None, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().0.contains("buffer"));

    let mut cursor = Cursor::new(b"\x02\x01\xff\xff\x08\x00\x00\x00");
    let result = ARSCHeader::read(&mut cursor, None, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().0.contains("smaller than header size"));

    let mut cursor = Cursor::new(b"\x02\x01\x01\x00\x08\x00\x00\x00");
    let result = ARSCHeader::read(&mut cursor, None, None);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .0
        .contains("declared header size is smaller"));

    let mut cursor = Cursor::new(b"\x02\x01\x08\x00\x04\x00\x00\x00");
    let result = ARSCHeader::read(&mut cursor, None, None);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .0
        .contains("declared chunk size is smaller"));

    let mut cursor =
        Cursor::new(b"\xca\xfe\x08\x00\x10\x00\x00\x00\xde\xea\xbe\xef\x42\x42\x42\x42");
    let h = ARSCHeader::read(&mut cursor, None, None).unwrap();
    assert_eq!(h.type_(), 0xFECA);
    assert_eq!(h.header_size, 8);
    assert_eq!(h.size, 16);
    assert_eq!(h.start, 0);
    assert_eq!(h.end(), 16);
}

#[test]
fn test_id_parsing() {
    let (res_id, package) = ARSCParser::parse_id("@DEADBEEF").unwrap();
    assert_eq!(res_id, 0xDEADBEEF);
    assert_eq!(package, None);

    let (res_id, package) = ARSCParser::parse_id("@android:DEADBEEF").unwrap();
    assert_eq!(res_id, 0xDEADBEEF);
    assert_eq!(package, Some("android".to_string()));

    let (res_id, package) = ARSCParser::parse_id("@foobar:01020304").unwrap();
    assert_eq!(res_id, 0x01020304);
    assert_eq!(package, Some("foobar".to_string()));

    assert!(ARSCParser::parse_id("whatisthis").is_err());
    assert!(ARSCParser::parse_id("#almost").is_err());
    assert!(ARSCParser::parse_id("@android:NONOTHEX").is_err());
    assert!(ARSCParser::parse_id("@android:00").is_err());
}

#[test]
fn test_arsc_parse_test_activity() {
    let path = test_dir().join("ARSC/TestActivity_resources.arsc");
    let data = std::fs::read(&path).unwrap();
    let arsc = ARSCParser::new(&data).unwrap();
    assert!(!arsc.get_packages_names().is_empty());
}

#[test]
fn test_arsc_parse_compact() {
    let path = test_dir().join("ARSC/compact-resources.arsc");
    let data = std::fs::read(&path).unwrap();
    let arsc = ARSCParser::new(&data).unwrap();
    assert!(!arsc.get_packages_names().is_empty());
}
