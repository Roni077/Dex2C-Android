//! Android manifest parsing stub.
//!
//! `axmldecoder` is excluded from this vendored crate; callers must use
//! `axml-parser` (`AXMLPrinter` / `AXMLParser`) for binary `AndroidManifest.xml`.

use crate::error::{Error, Result};

/// Parsed Android manifest (package, permissions, min/target SDK, etc.).
#[derive(Debug, Default, Clone)]
pub struct AndroidManifest {
    pub package: Option<String>,
    pub permissions: Vec<String>,
    pub uses_permissions: Vec<String>,
    pub min_sdk_version: Option<u32>,
    pub target_sdk_version: Option<u32>,
    pub version_code: Option<u32>,
    pub version_name: Option<String>,
}

/// Manifest parsing is disabled in `apkparser` (use `axml-parser` instead).
pub fn parse_manifest(_axml_bytes: &[u8]) -> Result<AndroidManifest> {
    Err(Error::Unsupported(
        "manifest parsing in apkparser is disabled; use axml-parser".into(),
    ))
}
