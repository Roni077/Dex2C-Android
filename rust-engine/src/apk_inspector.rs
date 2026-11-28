//! APK container, binary AXML manifest, `resources.arsc` resolution, and DEX 041
//! multi-container inspection backed by `androguard/axml-parser` and `androguard/apk-parser`.

use apkparser::{
    iter_logical_dexes, logical_dex_offsets, looks_like_apkm, ApkSignature, ApkmArchive,
    ApkmEntryKind, ZipArchive,
};
use axml_parser::{ARSCParser, AXMLPrinter};
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};

const NS_ANDROID_URI: &str = "http://schemas.android.com/apk/res/android";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestAndResourcesSummary {
    pub package_name: Option<String>,
    pub app_label: Option<String>,
    pub application_name: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<i64>,
    pub min_sdk: Option<i32>,
    pub target_sdk: Option<i32>,
    pub permissions: Vec<String>,
    pub is_packed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApkDexEntrySummary {
    pub entry_name: String,
    pub byte_size: usize,
    pub dex_version: String,
    pub is_dex041_container: bool,
    pub logical_dex_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApkSignatureSummary {
    pub is_signed: bool,
    pub is_signed_v1: bool,
    pub is_signed_v2: bool,
    pub is_signed_v3: bool,
    pub v1_signature_names: Vec<String>,
    pub v2_signer_count: usize,
    pub v3_signer_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApkArchiveSummary {
    pub is_apkm: bool,
    pub base_apk_name: Option<String>,
    pub apkm_splits: Vec<String>,
    pub manifest: Option<ManifestAndResourcesSummary>,
    pub native_abis: Vec<String>,
    pub dex_entries: Vec<ApkDexEntrySummary>,
    pub signature: Option<ApkSignatureSummary>,
}

/// Inspects `AndroidManifest.xml` (binary AXML or plaintext XML) and optional `resources.arsc`
/// to extract package ID, version info, SDK levels, permissions, app label, and `<application>` class.
pub fn inspect_manifest_and_resources(
    manifest_bytes: &[u8],
    arsc_bytes: Option<&[u8]>,
) -> Option<ManifestAndResourcesSummary> {
    if manifest_bytes.len() < 8 {
        return None;
    }

    let arsc = arsc_bytes.and_then(|b| ARSCParser::new(b).ok());
    let head_u16 = u16::from_le_bytes([manifest_bytes[0], manifest_bytes[1]]);

    let (xml_bytes, is_packed, printer_valid) = if head_u16 == 0x0003 {
        let printer = AXMLPrinter::new(manifest_bytes);
        let valid = printer.is_valid();
        let packed = printer.is_packed();
        let raw_xml = printer.get_xml(false);
        (raw_xml, packed, valid)
    } else {
        let trimmed = manifest_bytes
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .map(|idx| &manifest_bytes[idx..])
            .unwrap_or(&[]);
        if !trimmed.starts_with(b"<") {
            return None;
        }
        (manifest_bytes.to_vec(), false, true)
    };

    let xml_str = String::from_utf8_lossy(&xml_bytes);
    let summary = parse_manifest_xml(&xml_str, arsc.as_ref(), is_packed);

    if !printer_valid
        && summary.package_name.is_none()
        && summary.version_code.is_none()
        && summary.version_name.is_none()
        && summary.permissions.is_empty()
    {
        return None;
    }

    Some(summary)
}

pub fn inspect_manifest_and_resources_json(
    manifest_bytes: &[u8],
    arsc_bytes: Option<&[u8]>,
) -> Option<String> {
    let summary = inspect_manifest_and_resources(manifest_bytes, arsc_bytes)?;
    serde_json::to_string(&summary).ok()
}

/// Inspects a full `.apk` or `.apkm` archive buffer via `apkparser`, resolving manifest/ARSC
/// metadata, bundled native ABIs, root `classes*.dex` (with DEX 041 container detection), and
/// v1/v2/v3 APK signature summaries.
pub fn inspect_apk_archive(apk_bytes: &[u8]) -> Option<ApkArchiveSummary> {
    if apk_bytes.len() < 22 {
        return None;
    }

    let mut is_apkm = false;
    let mut base_apk_name: Option<String> = None;
    let mut apkm_splits: Vec<String> = Vec::new();
    let mut abi_set: BTreeSet<String> = BTreeSet::new();

    let primary_bytes_owned: Vec<u8>;
    let primary_bytes: &[u8] = if looks_like_apkm(apk_bytes) {
        let apkm = ApkmArchive::from_bytes(apk_bytes).ok()?;
        is_apkm = true;
        base_apk_name = Some(apkm.base_name().to_string());
        for entry in apkm.entries() {
            if entry.kind == ApkmEntryKind::Split {
                apkm_splits.push(entry.name.clone());
                if let Ok(split_bytes) = apkm.read(&entry.name) {
                    if let Ok(split_zip) = ZipArchive::parse_slice(&split_bytes) {
                        collect_abis_from_zip(&split_zip, &mut abi_set);
                    }
                }
            }
        }
        primary_bytes_owned = apkm.base_apk_bytes().ok()?;
        &primary_bytes_owned
    } else {
        apk_bytes
    };

    let zip = ZipArchive::parse_slice(primary_bytes).ok()?;
    collect_abis_from_zip(&zip, &mut abi_set);

    let manifest_bytes = zip.read("AndroidManifest.xml").ok();
    let arsc_bytes = zip.read("resources.arsc").ok();
    let manifest = manifest_bytes
        .as_deref()
        .and_then(|mb| inspect_manifest_and_resources(mb, arsc_bytes.as_deref()));

    let mut dex_names: Vec<String> = zip
        .names()
        .into_iter()
        .filter(|name| is_root_classes_dex(name))
        .collect();
    dex_names.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));

    let mut dex_entries = Vec::with_capacity(dex_names.len());
    for name in dex_names {
        if let Ok(dex_bytes) = zip.read(&name) {
            let dex_version = if dex_bytes.len() >= 8 && &dex_bytes[0..4] == b"dex\n" {
                String::from_utf8_lossy(&dex_bytes[4..7]).into_owned()
            } else {
                String::new()
            };
            let logical_offs = logical_dex_offsets(&dex_bytes);
            let is_container =
                dex_bytes.len() >= 8 && &dex_bytes[0..8] == b"dex\n041\0" && logical_offs.len() > 1;
            let logical_count = if logical_offs.is_empty() {
                1
            } else {
                logical_offs.len()
            };
            dex_entries.push(ApkDexEntrySummary {
                entry_name: name,
                byte_size: dex_bytes.len(),
                dex_version,
                is_dex041_container: is_container,
                logical_dex_count: logical_count,
            });
        }
    }

    let signature = ApkSignature::from_zip(primary_bytes, &zip)
        .ok()
        .map(|mut sig| {
            let is_v1 = sig.is_signed_v1();
            let is_v2 = sig.is_signed_v2();
            let is_v3 = sig.is_signed_v3();
            let v1_names = sig.get_signature_names();
            let v2_count = sig.get_certificates_der_v2().map(|v| v.len()).unwrap_or(0);
            let v3_count = sig.get_certificates_der_v3().map(|v| v.len()).unwrap_or(0);
            ApkSignatureSummary {
                is_signed: is_v1 || is_v2 || is_v3,
                is_signed_v1: is_v1,
                is_signed_v2: is_v2,
                is_signed_v3: is_v3,
                v1_signature_names: v1_names,
                v2_signer_count: v2_count,
                v3_signer_count: v3_count,
            }
        });

    Some(ApkArchiveSummary {
        is_apkm,
        base_apk_name,
        apkm_splits,
        manifest,
        native_abis: abi_set.into_iter().collect(),
        dex_entries,
        signature,
    })
}

pub fn inspect_apk_archive_json(apk_bytes: &[u8]) -> Option<String> {
    let summary = inspect_apk_archive(apk_bytes)?;
    serde_json::to_string(&summary).ok()
}

/// Splits a DEX `041` multi-section container via `apkparser::iter_logical_dexes`.
/// Returns an empty vector when the buffer contains at most one logical DEX so callers
/// can avoid copying normal DEX payloads across FFI.
pub fn split_dex041_container(entry_name: &str, dex_bytes: Vec<u8>) -> Vec<(String, Vec<u8>)> {
    let offs = logical_dex_offsets(&dex_bytes);
    if offs.len() <= 1 {
        return Vec::new();
    }
    iter_logical_dexes(entry_name, dex_bytes).collect()
}

fn collect_abis_from_zip(zip: &ZipArchive, abi_set: &mut BTreeSet<String>) {
    for name in zip.names() {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("lib/") && lower.ends_with(".so") {
            let mut parts = name.split('/');
            if let (Some(_), Some(abi), Some(_)) = (parts.next(), parts.next(), parts.next()) {
                if !abi.is_empty() {
                    abi_set.insert(abi.to_string());
                }
            }
        }
    }
}

fn is_root_classes_dex(name: &str) -> bool {
    if name.contains('/') {
        return false;
    }
    name == "classes.dex"
        || (name.starts_with("classes") && name.ends_with(".dex") && name.len() > "classes.dex".len())
}

fn parse_manifest_xml(
    xml: &str,
    arsc: Option<&ARSCParser>,
    is_packed: bool,
) -> ManifestAndResourcesSummary {
    let mut package_name: Option<String> = None;
    let mut raw_app_label: Option<String> = None;
    let mut raw_app_name: Option<String> = None;
    let mut raw_version_name: Option<String> = None;
    let mut version_code_low: Option<i64> = None;
    let mut version_code_major: Option<i64> = None;
    let mut min_sdk: Option<i32> = None;
    let mut target_sdk: Option<i32> = None;
    let mut permissions: Vec<String> = Vec::new();
    let mut seen_perms: HashSet<String> = HashSet::new();

    let mut android_prefixes: HashSet<String> = HashSet::new();
    android_prefixes.insert("android".to_string());

    let mut tag_stack: Vec<String> = Vec::new();
    let bytes = xml.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let Some(lt_rel) = bytes[i..].iter().position(|&b| b == b'<') else {
            break;
        };
        i += lt_rel + 1;
        if i >= bytes.len() {
            break;
        }

        // Skip XML comments <!-- ... -->
        if bytes[i..].starts_with(b"!--") {
            if let Some(end_rel) = find_subslice(&bytes[i + 3..], b"-->") {
                i = i + 3 + end_rel + 3;
            } else {
                break;
            }
            continue;
        }
        // Skip processing instructions <?...?> or <!DOCTYPE ...>
        if bytes[i] == b'?' || bytes[i] == b'!' {
            if let Some(gt_rel) = find_tag_end(&bytes[i..]) {
                i += gt_rel + 1;
            } else {
                break;
            }
            continue;
        }

        let Some(gt_rel) = find_tag_end(&bytes[i..]) else {
            break;
        };
        let raw_tag_body = &xml[i..i + gt_rel];
        i += gt_rel + 1;

        let trimmed = raw_tag_body.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(close_name) = trimmed.strip_prefix('/') {
            let local_close = close_name
                .split_whitespace()
                .next()
                .unwrap_or("")
                .rsplit(':')
                .next()
                .unwrap_or("")
                .trim_matches('\0')
                .to_ascii_lowercase();
            if let Some(pos) = tag_stack.iter().rposition(|t| t == &local_close) {
                tag_stack.truncate(pos);
            }
            continue;
        }

        let (self_closing, body_no_slash) = if let Some(stripped) = trimmed.strip_suffix('/') {
            (true, stripped.trim_end())
        } else {
            (false, trimmed)
        };

        let (tag_name_raw, attrs_str) = split_tag_and_attrs(body_no_slash);
        let tag_local = tag_name_raw
            .rsplit(':')
            .next()
            .unwrap_or(tag_name_raw)
            .trim_matches('\0')
            .to_ascii_lowercase();

        let attrs = parse_xml_attributes(attrs_str);
        for (k, v) in &attrs {
            if let Some(prefix) = k.strip_prefix("xmlns:") {
                if v.trim() == NS_ANDROID_URI {
                    android_prefixes.insert(prefix.to_string());
                }
            }
        }

        tag_stack.push(tag_local.clone());
        let in_manifest = tag_stack.len() == 1 && tag_local == "manifest";
        let under_manifest = tag_stack.len() == 2 && tag_stack[0] == "manifest";

        if in_manifest {
            for (k, v) in &attrs {
                let (ns_prefix, local) = split_attr_key(k);
                match local {
                    "package" if ns_prefix.is_empty() => {
                        let clean = v.trim();
                        if !clean.is_empty() && package_name.is_none() {
                            package_name = Some(clean.to_string());
                        }
                    }
                    "versionCode" if is_android_or_unprefixed(ns_prefix, &android_prefixes) => {
                        if let Some(code) = parse_int_or_hex(v) {
                            version_code_low = Some(code);
                        }
                    }
                    "versionCodeMajor"
                        if is_android_or_unprefixed(ns_prefix, &android_prefixes) =>
                    {
                        if let Some(major) = parse_int_or_hex(v) {
                            version_code_major = Some(major);
                        }
                    }
                    "versionName" if is_android_or_unprefixed(ns_prefix, &android_prefixes) => {
                        let clean = v.trim();
                        if !clean.is_empty() && raw_version_name.is_none() {
                            raw_version_name = Some(clean.to_string());
                        }
                    }
                    _ => {}
                }
            }
        } else if under_manifest && tag_local == "uses-sdk" {
            for (k, v) in &attrs {
                let (ns_prefix, local) = split_attr_key(k);
                if !is_android_or_unprefixed(ns_prefix, &android_prefixes) {
                    continue;
                }
                match local {
                    "minSdkVersion" => {
                        if let Some(sdk) = parse_sdk_int(v) {
                            min_sdk = Some(sdk);
                        }
                    }
                    "targetSdkVersion" => {
                        if let Some(sdk) = parse_sdk_int(v) {
                            target_sdk = Some(sdk);
                        }
                    }
                    _ => {}
                }
            }
        } else if under_manifest && tag_local == "application" {
            for (k, v) in &attrs {
                let (ns_prefix, local) = split_attr_key(k);
                if !is_android_or_unprefixed(ns_prefix, &android_prefixes) {
                    continue;
                }
                match local {
                    "label" => {
                        let clean = v.trim();
                        if !clean.is_empty() && raw_app_label.is_none() {
                            raw_app_label = Some(clean.to_string());
                        }
                    }
                    "name" => {
                        let clean = v.trim();
                        if !clean.is_empty() && raw_app_name.is_none() {
                            raw_app_name = Some(clean.to_string());
                        }
                    }
                    _ => {}
                }
            }
        } else if under_manifest
            && (tag_local == "uses-permission" || tag_local == "uses-permission-sdk-23")
        {
            for (k, v) in &attrs {
                let (ns_prefix, local) = split_attr_key(k);
                if local == "name" && is_android_or_unprefixed(ns_prefix, &android_prefixes) {
                    let perm = v.trim();
                    if !perm.is_empty() && seen_perms.insert(perm.to_string()) {
                        permissions.push(perm.to_string());
                    }
                }
            }
        }

        if self_closing {
            tag_stack.pop();
        }
    }

    let version_code = match (version_code_major, version_code_low) {
        (Some(major), Some(low)) => Some((major << 32) | (low & 0xFFFF_FFFF)),
        (None, Some(low)) => Some(low),
        _ => None,
    };

    let app_label = raw_app_label.and_then(|raw| resolve_manifest_string_or_ref(&raw, arsc));
    let version_name = raw_version_name.and_then(|raw| resolve_manifest_string_or_ref(&raw, arsc));
    let application_name = raw_app_name.map(|raw| normalize_component_name(&raw, package_name.as_deref()));

    ManifestAndResourcesSummary {
        package_name,
        app_label,
        application_name,
        version_name,
        version_code,
        min_sdk,
        target_sdk,
        permissions,
        is_packed,
    }
}

fn resolve_manifest_string_or_ref(raw: &str, arsc: Option<&ARSCParser>) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed.starts_with('@') {
        return Some(trimmed.to_string());
    }
    let parser = arsc?;
    resolve_arsc_reference(parser, trimmed, 0)
}

fn resolve_arsc_reference(arsc: &ARSCParser, reference: &str, depth: usize) -> Option<String> {
    if depth >= 4 {
        return None;
    }
    let trimmed = reference.trim();
    let body = trimmed.strip_prefix('@')?;

    if let Some(hex) = body
        .strip_prefix("android:")
        .or_else(|| body.strip_prefix("0x"))
        .or_else(|| body.strip_prefix("0X"))
        .or(Some(body))
    {
        if hex.len() == 8 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(res_id) = u32::from_str_radix(hex, 16) {
                let candidate = arsc
                    .resources
                    .get(&res_id)
                    .and_then(|e| e.value.as_deref())
                    .or_else(|| {
                        arsc.all_entries
                            .iter()
                            .find(|e| e.id == res_id && e.value.is_some())
                            .and_then(|e| e.value.as_deref())
                    })?;
                if candidate.starts_with('@') {
                    return resolve_arsc_reference(arsc, candidate, depth + 1);
                }
                return (!candidate.is_empty()).then(|| candidate.to_string());
            }
        }
    }

    // Also resolve symbolic `@string/app_name` or `@android:string/ok` references when present in XML.
    if let Some((res_type, res_name)) = body
        .strip_prefix("android:")
        .unwrap_or(body)
        .split_once('/')
    {
        let entry = arsc
            .resources
            .values()
            .find(|e| e.type_name == res_type && e.name == res_name && e.value.is_some())
            .or_else(|| {
                arsc.all_entries
                    .iter()
                    .find(|e| e.type_name == res_type && e.name == res_name && e.value.is_some())
            })?;
        let val = entry.value.as_deref()?;
        if val.starts_with('@') {
            return resolve_arsc_reference(arsc, val, depth + 1);
        }
        return (!val.is_empty()).then(|| val.to_string());
    }

    None
}

fn normalize_component_name(raw: &str, package_name: Option<&str>) -> String {
    let trimmed = raw.trim();
    match package_name {
        Some(pkg) if trimmed.starts_with('.') => format!("{pkg}{trimmed}"),
        Some(pkg) if !trimmed.contains('.') => format!("{pkg}.{trimmed}"),
        _ => trimmed.to_string(),
    }
}

fn split_attr_key(raw: &str) -> (&str, &str) {
    if let Some(stripped) = raw.strip_prefix('{') {
        if let Some((ns, local)) = stripped.split_once('}') {
            return (ns, local);
        }
    }
    if let Some((prefix, local)) = raw.split_once(':') {
        (prefix, local)
    } else {
        ("", raw)
    }
}

fn is_android_or_unprefixed(ns_prefix: &str, android_prefixes: &HashSet<String>) -> bool {
    ns_prefix.is_empty()
        || ns_prefix == NS_ANDROID_URI
        || android_prefixes.contains(ns_prefix)
}

fn parse_int_or_hex(raw: &str) -> Option<i64> {
    let t = raw.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok().map(|v| v as i64)
    } else {
        t.parse::<i64>().ok()
    }
}

fn parse_sdk_int(raw: &str) -> Option<i32> {
    parse_int_or_hex(raw).and_then(|v| i32::try_from(v).ok())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn find_tag_end(bytes: &[u8]) -> Option<usize> {
    let mut quote: Option<u8> = None;
    for (idx, &b) in bytes.iter().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(idx),
            _ => {}
        }
    }
    None
}

fn split_tag_and_attrs(body: &str) -> (&str, &str) {
    match body.find(char::is_whitespace) {
        Some(idx) => (&body[..idx], &body[idx + 1..]),
        None => (body, ""),
    }
}

fn parse_xml_attributes(input: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' {
            i += 1;
        }
        let raw_name = input[name_start..i].trim();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let quote = bytes[i];
        if quote != b'"' && quote != b'\'' {
            let val_start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            out.push((raw_name.to_string(), unescape_xml(&input[val_start..i])));
            continue;
        }
        i += 1;
        let val_start = i;
        while i < bytes.len() && bytes[i] != quote {
            i += 1;
        }
        let raw_val = &input[val_start..i];
        if i < bytes.len() {
            i += 1;
        }
        if !raw_name.is_empty() {
            out.push((raw_name.to_string(), unescape_xml(raw_val)));
        }
    }

    out
}

fn unescape_xml(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        if let Some(semi) = after.find(';') {
            let ent = &after[..semi];
            match ent {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                    if let Ok(cp) = u32::from_str_radix(&ent[2..], 16) {
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                        }
                    }
                }
                _ if ent.starts_with('#') => {
                    if let Ok(cp) = ent[1..].parse::<u32>() {
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                        }
                    }
                }
                _ => {
                    out.push('&');
                    out.push_str(ent);
                    out.push(';');
                }
            }
            rest = &after[semi + 1..];
        } else {
            out.push('&');
            rest = after;
            break;
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axml_parser::{
        build_arsc, encode_xml, ArscBuildConfig, ArscBuildEntry, ArscBuildInput, ArscBuildType,
        ArscBuildValue,
    };
    use dex_parser::{BuiltClass, DexBuilder, DexFile};
    use std::io::Write;
    use std::path::PathBuf;

    fn axml_fixture(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("vendor")
            .join("axml-parser")
            .join("tests")
            .join(rel)
    }

    #[test]
    fn test_real_world_namespace_quirk_axml_manifests() {
        let fixtures = [
            "AXML/AndroidManifest.xml",
            "AXML/AndroidManifest_NamespaceInAttributeName.xml",
            "AXML/AndroidManifest_NamespaceInAttributeName2.xml",
            "AXML/AndroidManifestDoubleNamespace.xml",
            "AXML/AndroidManifestExtraNamespace.xml",
            "AXML/AndroidManifestMaskingNamespace.xml",
            "AXML/AndroidManifestLiapp.xml",
            "AXML/AndroidManifestNullbytes.xml",
            "AXML/AndroidManifestUTF8Strings.xml",
        ];

        for rel in fixtures {
            let bytes = std::fs::read(axml_fixture(rel)).expect("fixture exists");
            let summary = inspect_manifest_and_resources(&bytes, None)
                .unwrap_or_else(|| panic!("expected valid manifest summary for {rel}"));
            let pkg = summary.package_name.as_deref().unwrap_or("");
            assert!(
                !pkg.is_empty(),
                "expected non-empty package_name for {rel}, got {summary:?}"
            );
        }
    }

    #[test]
    fn test_manifest_resolves_arsc_app_label_sdk_version_and_application_name() {
        let arsc_bytes = build_arsc(&ArscBuildInput {
            package_id: 0x7F,
            package_name: "com.example.shop".to_string(),
            types: vec![ArscBuildType {
                name: "string".to_string(),
                type_id: 0,
                configs: vec![ArscBuildConfig {
                    entries: vec![
                        ArscBuildEntry {
                            entry_index: 0,
                            name: "app_name".to_string(),
                            value: ArscBuildValue::String("Shop Demo App".to_string()),
                            public: true,
                        },
                        ArscBuildEntry {
                            entry_index: 1,
                            name: "ver_name".to_string(),
                            value: ArscBuildValue::String("3.4.5".to_string()),
                            public: true,
                        },
                    ],
                    ..Default::default()
                }],
            }],
        })
        .expect("build ARSC");

        // Compute exact generated IDs via ARSCParser so the manifest references them.
        let arsc = ARSCParser::new(&arsc_bytes).expect("parse built ARSC");
        let label_id = arsc
            .resources
            .values()
            .find(|e| e.name == "app_name")
            .expect("app_name entry")
            .id;
        let ver_id = arsc
            .resources
            .values()
            .find(|e| e.name == "ver_name")
            .expect("ver_name entry")
            .id;

        let xml = format!(
            r#"<manifest xmlns:android="http://schemas.android.com/apk/res/android"
                package="com.example.shop"
                android:versionCode="42"
                android:versionName="@{ver_id:08X}">
                <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="36" />
                <uses-permission android:name="android.permission.INTERNET" />
                <application android:label="@{label_id:08X}" android:name=".ShopApplication">
                    <activity android:name=".MainActivity" android:label="Wrong Activity Label" />
                </application>
            </manifest>"#
        );
        let axml_bytes = encode_xml(xml.as_bytes()).expect("encode binary AXML");

        let summary = inspect_manifest_and_resources(&axml_bytes, Some(&arsc_bytes))
            .expect("manifest + arsc summary");

        assert_eq!(summary.package_name.as_deref(), Some("com.example.shop"));
        assert_eq!(summary.app_label.as_deref(), Some("Shop Demo App"));
        assert_eq!(
            summary.application_name.as_deref(),
            Some("com.example.shop.ShopApplication")
        );
        assert_eq!(summary.version_code, Some(42));
        assert_eq!(summary.version_name.as_deref(), Some("3.4.5"));
        assert_eq!(summary.min_sdk, Some(24));
        assert_eq!(summary.target_sdk, Some(36));
        assert_eq!(summary.permissions, vec!["android.permission.INTERNET"]);
    }

    #[test]
    fn test_dex041_container_splits_and_parses_each_logical_dex() {
        fn build_single_class(descriptor: &str) -> Vec<u8> {
            let mut b = DexBuilder::new();
            b.add_class(BuiltClass {
                descriptor: descriptor.to_string(),
                access_flags: 1,
                superclass: Some("Ljava/lang/Object;".into()),
                interfaces: vec![],
                source_file: None,
                static_fields: vec![],
                instance_fields: vec![],
                direct_methods: vec![],
                virtual_methods: vec![],
                annotations: Default::default(),
            });
            let mut raw = b.finish().expect("build dex");
            raw[4..8].copy_from_slice(b"041\0");
            raw
        }

        // Two concatenated DEX sections where section 2 offsets are relocated to container-absolute.
        let dex1 = build_single_class("Lcom/example/One;");
        let mut dex2 = build_single_class("Lcom/example/Two;");
        let sec2_base = dex1.len() as u32;
        // Adjust header table offsets in dex2 so they are container-absolute inside `[dex1 || dex2]`.
        for off in [0x34usize, 0x3C, 0x44, 0x4C, 0x54, 0x5C, 0x64, 0x6C] {
            let val = u32::from_le_bytes(dex2[off..off + 4].try_into().unwrap());
            if val != 0 {
                dex2[off..off + 4].copy_from_slice(&(val + sec2_base).to_le_bytes());
            }
        }
        // Adjust string_data_off entries in string_ids table of dex2
        let s_size = u32::from_le_bytes(dex2[0x38..0x3C].try_into().unwrap());
        let s_off_local = u32::from_le_bytes(dex2[0x3C..0x40].try_into().unwrap()) - sec2_base;
        for idx in 0..s_size as usize {
            let p = s_off_local as usize + idx * 4;
            let s_data_off = u32::from_le_bytes(dex2[p..p + 4].try_into().unwrap());
            dex2[p..p + 4].copy_from_slice(&(s_data_off + sec2_base).to_le_bytes());
        }
        // Adjust interfaces_off / class_data_off / map_list item offsets if present: minimal empty class has 0s,
        // update map_off item offsets if map_off != 0.
        let map_off_rel = u32::from_le_bytes(dex2[0x34..0x38].try_into().unwrap());
        if map_off_rel != 0 {
            let mp = (map_off_rel - sec2_base) as usize;
            let count = u32::from_le_bytes(dex2[mp..mp + 4].try_into().unwrap()) as usize;
            for idx in 0..count {
                let item_off_pos = mp + 4 + idx * 12 + 8;
                let item_off = u32::from_le_bytes(dex2[item_off_pos..item_off_pos + 4].try_into().unwrap());
                dex2[item_off_pos..item_off_pos + 4].copy_from_slice(&(item_off + sec2_base).to_le_bytes());
            }
        }

        let mut container = Vec::with_capacity(dex1.len() + dex2.len());
        container.extend_from_slice(&dex1);
        container.extend_from_slice(&dex2);

        let parts = split_dex041_container("classes.dex", container);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].0, "classes.dex!classes1.dex");
        assert_eq!(parts[1].0, "classes.dex!classes2.dex");

        let parsed1 = DexFile::parse(&parts[0].1).expect("parse section 1");
        let parsed2 = DexFile::parse(&parts[1].1).expect("parse section 2");
        let cls1 = parsed1.get_class_def(0).expect("section 1 class_def");
        let cls2 = parsed2.get_class_def(0).expect("section 2 class_def");
        assert_eq!(parsed1.get_type(cls1.class_idx).unwrap(), "Lcom/example/One;");
        assert_eq!(parsed2.get_type(cls2.class_idx).unwrap(), "Lcom/example/Two;");
        let engine_parsed2 = crate::dex::DexFile::parse(&parts[1].1).expect("engine parse section 2");
        assert_eq!(engine_parsed2.get_class_def_full(0).unwrap().descriptor, "Lcom/example/Two;");
    }

    #[test]
    fn test_inspect_apk_and_apkm_archive() {
        let mut apk_buf = std::io::Cursor::new(Vec::new());
        {
            let mut zw = apk_zip_writer(&mut apk_buf);
            let xml = r#"<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo.apkm" android:versionCode="7" android:versionName="1.7"><uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/><application android:label="DemoApp" android:name="com.demo.apkm.App"/></manifest>"#;
            let axml = encode_xml(xml.as_bytes()).unwrap();
            zw.start_file("AndroidManifest.xml", Default::default()).unwrap();
            zw.write_all(&axml).unwrap();
            zw.start_file("classes.dex", Default::default()).unwrap();
            zw.write_all(b"dex\n039\0").unwrap();
            zw.write_all(&[0u8; 0x68]).unwrap();
            zw.start_file("lib/arm64-v8a/libnative.so", Default::default()).unwrap();
            zw.write_all(b"\x7fELF").unwrap();
            zw.finish().unwrap();
        }
        let base_apk_bytes = apk_buf.into_inner();

        let direct = inspect_apk_archive(&base_apk_bytes).expect("apk archive");
        assert!(!direct.is_apkm);
        assert_eq!(direct.native_abis, vec!["arm64-v8a"]);
        assert_eq!(direct.manifest.as_ref().unwrap().package_name.as_deref(), Some("com.demo.apkm"));
        assert_eq!(direct.manifest.as_ref().unwrap().app_label.as_deref(), Some("DemoApp"));

        let mut apkm_buf = std::io::Cursor::new(Vec::new());
        {
            let mut zw = apk_zip_writer(&mut apkm_buf);
            zw.start_file("base.apk", Default::default()).unwrap();
            zw.write_all(&base_apk_bytes).unwrap();
            zw.finish().unwrap();
        }
        let apkm_summary = inspect_apk_archive(&apkm_buf.into_inner()).expect("apkm archive");
        assert!(apkm_summary.is_apkm);
        assert_eq!(apkm_summary.base_apk_name.as_deref(), Some("base.apk"));
        assert_eq!(
            apkm_summary.manifest.as_ref().unwrap().application_name.as_deref(),
            Some("com.demo.apkm.App")
        );
    }

    fn apk_zip_writer<W: Write + std::io::Seek>(w: W) -> zip_test::ZipWriter<W> {
        zip_test::ZipWriter::new(w)
    }

    use zip as zip_test;
}
