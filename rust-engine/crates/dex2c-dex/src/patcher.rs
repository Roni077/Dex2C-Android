//! In-place DEX bytecode method patcher and checksum re-signer.
//! Replaces transpiled method bytecode with native stubs (ACC_NATIVE = 0x0100, code_off = 0)
//! and recomputes the Adler32 checksum and SHA-1 signature via `dex_parser::fix_checksums`.

use dex2c_core::{Dex2cError, Result};
use dex_parser::leb128::{read_uleb128, write_uleb128};
use dex_parser::{fix_checksums, DexHeader};
use std::collections::HashSet;

pub const ACC_NATIVE: u32 = 0x0100;

pub fn patch_dex_methods_native(
    dex_bytes: &mut [u8],
    native_method_indices: &HashSet<u32>,
) -> Result<usize> {
    let header = DexHeader::parse(dex_bytes)
        .map_err(|e| Dex2cError::DexFormat(format!("DEX too small/invalid to patch: {e}")))?;

    let mut patched_count = 0usize;

    for c in 0..header.class_defs_size as usize {
        let base = header.class_defs_off as usize + c * 32;
        if base + 32 > dex_bytes.len() {
            break;
        }

        let class_data_off = u32::from_le_bytes([
            dex_bytes[base + 24],
            dex_bytes[base + 25],
            dex_bytes[base + 26],
            dex_bytes[base + 27],
        ]) as usize;

        if class_data_off == 0 || class_data_off >= dex_bytes.len() {
            continue;
        }

        let mut cursor = class_data_off;
        let (static_fields, n1) = match read_uleb128(dex_bytes, cursor) {
            Some(p) => p,
            None => continue,
        };
        cursor += n1;
        let (instance_fields, n2) = match read_uleb128(dex_bytes, cursor) {
            Some(p) => p,
            None => continue,
        };
        cursor += n2;
        let (direct_methods, n3) = match read_uleb128(dex_bytes, cursor) {
            Some(p) => p,
            None => continue,
        };
        cursor += n3;
        let (virtual_methods, n4) = match read_uleb128(dex_bytes, cursor) {
            Some(p) => p,
            None => continue,
        };
        cursor += n4;

        // Skip fields
        for _ in 0..(static_fields + instance_fields) {
            let Some((_, k1)) = read_uleb128(dex_bytes, cursor) else {
                break;
            };
            cursor += k1;
            let Some((_, k2)) = read_uleb128(dex_bytes, cursor) else {
                break;
            };
            cursor += k2;
        }

        for count in [direct_methods, virtual_methods] {
            let mut last_idx = 0u32;
            for _ in 0..count {
                let Some((idx_diff, d1)) = read_uleb128(dex_bytes, cursor) else {
                    break;
                };
                let Some((flags, d2)) = read_uleb128(dex_bytes, cursor + d1) else {
                    break;
                };
                let Some((code_off, d3)) = read_uleb128(dex_bytes, cursor + d1 + d2) else {
                    break;
                };
                let entry_end = cursor + d1 + d2 + d3;
                last_idx += idx_diff;

                if native_method_indices.contains(&last_idx) && code_off != 0 {
                    let new_flags = flags | ACC_NATIVE;
                    let mut re_encoded = Vec::with_capacity(8);
                    re_encoded.extend(write_uleb128(idx_diff));
                    re_encoded.extend(write_uleb128(new_flags));
                    re_encoded.extend(write_uleb128(0)); // code_off = 0

                    let original_len = entry_end - cursor;
                    if re_encoded.len() <= original_len {
                        dex_bytes[cursor..cursor + re_encoded.len()].copy_from_slice(&re_encoded);
                    }
                    patched_count += 1;
                }
                cursor = entry_end;
            }
        }
    }

    resign_dex_header(dex_bytes)?;
    Ok(patched_count)
}

pub fn resign_dex_header(dex_bytes: &mut [u8]) -> Result<()> {
    fix_checksums(dex_bytes).map_err(|e| Dex2cError::DexFormat(e.to_string()))
}
