//! ZIP alignment for APK signing (`zipalign -p` semantics).

use super::{central_dir_offset, find_eocd, SignError, SignResult};

const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const CDH_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
pub const PAGE_ALIGNMENT: u32 = 16384;
const DEFAULT_ALIGNMENT: u32 = 4;

/// Align uncompressed entries: `.so` → `alignment` bytes (e.g. `16384`), others → 4 bytes.
/// Rebuilds local headers + central directory offsets (does not change compression).
pub fn zipalign(apk: &[u8], alignment: u32) -> SignResult<Vec<u8>> {
    zipalign_with_page_alignment(apk, alignment)
}

/// Align uncompressed entries using `PAGE_ALIGNMENT` (`16384`) for `.so` and `4` bytes for others.
pub fn zipalign_page(apk: &[u8]) -> SignResult<Vec<u8>> {
    zipalign_with_page_alignment(apk, PAGE_ALIGNMENT)
}

/// Align uncompressed entries: `.so` → `so_page_alignment` bytes, others → 4 bytes.
pub fn zipalign_with_page_alignment(apk: &[u8], so_page_alignment: u32) -> SignResult<Vec<u8>> {
    let cd_off = central_dir_offset(apk)?;
    let eocd = find_eocd(apk).ok_or_else(|| SignError::InvalidApk("EOCD not found".into()))?;
    if eocd < cd_off {
        return Err(SignError::InvalidApk("EOCD before central directory".into()));
    }

    // Parse Central Directory first so entries written with ZIP Data Descriptors
    // (`flag & 0x0008`, e.g. Java ZipOutputStream where LFH compressed_size == 0)
    // still resolve exact compressed_size, crc32, and local_header_offset.
    struct CdRecord {
        lfh_off: usize,
        cd_pos: usize,
        name: String,
        flags: u16,
        comp_method: u16,
        crc32: u32,
        comp_size: u32,
        uncomp_size: u32,
        name_len: usize,
        extra_len: usize,
        comment_len: usize,
    }

    let mut cd_records = Vec::new();
    let mut cd_pos = cd_off;
    while cd_pos + 46 <= eocd {
        if apk[cd_pos..cd_pos + 4] != CDH_SIG {
            break;
        }
        let flags = u16::from_le_bytes([apk[cd_pos + 8], apk[cd_pos + 9]]);
        let comp_method = u16::from_le_bytes([apk[cd_pos + 10], apk[cd_pos + 11]]);
        let crc32 = u32::from_le_bytes(apk[cd_pos + 16..cd_pos + 20].try_into().unwrap());
        let comp_size = u32::from_le_bytes(apk[cd_pos + 20..cd_pos + 24].try_into().unwrap());
        let uncomp_size = u32::from_le_bytes(apk[cd_pos + 24..cd_pos + 28].try_into().unwrap());
        let name_len = u16::from_le_bytes([apk[cd_pos + 28], apk[cd_pos + 29]]) as usize;
        let extra_len = u16::from_le_bytes([apk[cd_pos + 30], apk[cd_pos + 31]]) as usize;
        let comment_len = u16::from_le_bytes([apk[cd_pos + 32], apk[cd_pos + 33]]) as usize;
        let lfh_off = u32::from_le_bytes(apk[cd_pos + 42..cd_pos + 46].try_into().unwrap()) as usize;
        let rec_len = 46 + name_len + extra_len + comment_len;
        if cd_pos + rec_len > eocd || cd_pos + 46 + name_len > apk.len() {
            return Err(SignError::InvalidApk("Truncated central directory record".into()));
        }
        let name = String::from_utf8_lossy(&apk[cd_pos + 46..cd_pos + 46 + name_len]).into_owned();
        cd_records.push(CdRecord {
            lfh_off,
            cd_pos,
            name,
            flags,
            comp_method,
            crc32,
            comp_size,
            uncomp_size,
            name_len,
            extra_len,
            comment_len,
        });
        cd_pos += rec_len;
    }

    cd_records.sort_by_key(|r| r.lfh_off);

    let mut out = Vec::with_capacity(apk.len() + cd_records.len() * 64);
    let mut new_offsets = Vec::with_capacity(cd_records.len());
    let mut new_pads = Vec::with_capacity(cd_records.len());

    for rec in &cd_records {
        let pos = rec.lfh_off;
        if pos + 30 > cd_off || apk[pos..pos + 4] != LFH_SIG {
            return Err(SignError::InvalidApk(format!(
                "Invalid local file header for {}",
                rec.name
            )));
        }
        let lfh_name_len = u16::from_le_bytes([apk[pos + 26], apk[pos + 27]]) as usize;
        let lfh_extra_len = u16::from_le_bytes([apk[pos + 28], apk[pos + 29]]) as usize;
        let header_size = 30 + lfh_name_len + lfh_extra_len;
        let data_start = pos + header_size;
        let data_len = rec.comp_size as usize;
        let data_end = data_start + data_len;
        if data_end > cd_off {
            return Err(SignError::InvalidApk(format!(
                "Truncated entry data for {}",
                rec.name
            )));
        }

        let align = entry_alignment(&rec.name, rec.comp_method, so_page_alignment);
        let lfh_start = out.len();
        new_offsets.push(lfh_start as u32);

        let base_data_start = lfh_start + 30 + lfh_name_len + lfh_extra_len;
        let pad = if align > 1 {
            let m = (base_data_start as u32) % align;
            if m == 0 {
                0
            } else {
                (align - m) as usize
            }
        } else {
            0
        };
        new_pads.push(pad);
        let new_extra = lfh_extra_len + pad;

        let mut lfh = apk[pos..data_start].to_vec();
        // Normalize Data Descriptor bit (0x0008) by backfilling CD sizes into LFH
        // so both Android PackageParser and apksigner see self-contained LFHs.
        let normalized_flags = rec.flags & !0x0008u16;
        lfh[6..8].copy_from_slice(&normalized_flags.to_le_bytes());
        lfh[14..18].copy_from_slice(&rec.crc32.to_le_bytes());
        lfh[18..22].copy_from_slice(&rec.comp_size.to_le_bytes());
        lfh[22..26].copy_from_slice(&rec.uncomp_size.to_le_bytes());
        lfh[28..30].copy_from_slice(&(new_extra as u16).to_le_bytes());

        out.extend_from_slice(&lfh);
        if pad > 0 {
            out.extend(std::iter::repeat_n(0u8, pad));
        }
        out.extend_from_slice(&apk[data_start..data_end]);
    }

    let new_cd_off = out.len();

    // Rewrite central directory preserving original record order with updated offsets & extra padding.
    let mut order_map: Vec<usize> = (0..cd_records.len()).collect();
    order_map.sort_by_key(|&idx| cd_records[idx].cd_pos);

    for idx in order_map {
        let rec = &cd_records[idx];
        let cpos = rec.cd_pos;
        let lfh_extra_end = rec.lfh_off + 30 + u16::from_le_bytes([apk[rec.lfh_off + 26], apk[rec.lfh_off + 27]]) as usize + u16::from_le_bytes([apk[rec.lfh_off + 28], apk[rec.lfh_off + 29]]) as usize;
        let lfh_name_len = u16::from_le_bytes([apk[rec.lfh_off + 26], apk[rec.lfh_off + 27]]) as usize;
        let lfh_extra_slice = &apk[rec.lfh_off + 30 + lfh_name_len..lfh_extra_end];
        let new_extra = lfh_extra_slice.len() + new_pads[idx];
        let normalized_flags = rec.flags & !0x0008u16;

        out.extend_from_slice(&apk[cpos..cpos + 8]);
        out.extend_from_slice(&normalized_flags.to_le_bytes());
        out.extend_from_slice(&apk[cpos + 10..cpos + 30]);
        out.extend_from_slice(&(new_extra as u16).to_le_bytes());
        out.extend_from_slice(&apk[cpos + 32..cpos + 42]);
        out.extend_from_slice(&new_offsets[idx].to_le_bytes());
        out.extend_from_slice(&apk[cpos + 46..cpos + 46 + rec.name_len]);
        out.extend_from_slice(lfh_extra_slice);
        if new_pads[idx] > 0 {
            out.extend(std::iter::repeat_n(0u8, new_pads[idx]));
        }
        out.extend_from_slice(
            &apk[cpos + 46 + rec.name_len + rec.extra_len
                ..cpos + 46 + rec.name_len + rec.extra_len + rec.comment_len],
        );
    }

    // EOCD with updated CD size + offset (padding grows the central directory).
    let eocd_start = out.len();
    let cd_size = eocd_start - new_cd_off;
    out.extend_from_slice(&apk[eocd..]);
    if out.len() >= eocd_start + 22 {
        out[eocd_start + 12..eocd_start + 16]
            .copy_from_slice(&(cd_size as u32).to_le_bytes());
        out[eocd_start + 16..eocd_start + 20]
            .copy_from_slice(&(new_cd_off as u32).to_le_bytes());
    }
    Ok(out)
}

fn entry_alignment(name: &str, comp_method: u16, so_page_alignment: u32) -> u32 {
    if comp_method != 0 {
        return 0; // compressed: no alignment requirement
    }
    if name.starts_with("lib/") && name.ends_with(".so") {
        so_page_alignment.max(DEFAULT_ALIGNMENT)
    } else {
        DEFAULT_ALIGNMENT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{align_and_sign, SignOptions};
    use crate::zip::ZipArchive;
    use crate::zip_write::ApkWriter;

    fn entry_data_offset(apk: &[u8], target_name: &str) -> Option<usize> {
        let cd_off = central_dir_offset(apk).ok()?;
        let mut pos = 0usize;
        while pos + 30 <= cd_off {
            if apk[pos..pos + 4] != LFH_SIG {
                break;
            }
            let comp_size = u32::from_le_bytes(apk[pos + 18..pos + 22].try_into().unwrap()) as usize;
            let name_len = u16::from_le_bytes([apk[pos + 26], apk[pos + 27]]) as usize;
            let extra_len = u16::from_le_bytes([apk[pos + 28], apk[pos + 29]]) as usize;
            let data_start = pos + 30 + name_len + extra_len;
            let name = String::from_utf8_lossy(&apk[pos + 30..pos + 30 + name_len]);
            if name == target_name {
                return Some(data_start);
            }
            pos = data_start + comp_size;
        }
        None
    }

    #[test]
    fn zipalign_honors_16384_for_so_and_4_for_non_so() {
        assert_eq!(PAGE_ALIGNMENT, 16384);

        let mut writer = ApkWriter::new();
        writer.add_entry("resources.arsc", b"ARSC_DUMMY_DATA_12345", false);
        writer.add_entry("lib/arm64-v8a/libnative.so", b"\x7fELF_TEST_SO_DATA", false);
        writer.add_entry("classes.dex", b"dex\n035\0", true);
        let raw_apk = writer.finish().unwrap();

        let aligned = zipalign(&raw_apk, PAGE_ALIGNMENT).unwrap();
        let arsc_off = entry_data_offset(&aligned, "resources.arsc").expect("resources.arsc present");
        let so_off =
            entry_data_offset(&aligned, "lib/arm64-v8a/libnative.so").expect("libnative.so present");

        assert_eq!(arsc_off % 4, 0, "resources.arsc must be 4-byte aligned");
        assert_eq!(so_off % 16384, 0, ".so entry must be 16384-byte aligned (got offset {so_off})");

        let archive = ZipArchive::parse(aligned).unwrap();
        assert_eq!(archive.read("resources.arsc").unwrap(), b"ARSC_DUMMY_DATA_12345");
        assert_eq!(
            archive.read("lib/arm64-v8a/libnative.so").unwrap(),
            b"\x7fELF_TEST_SO_DATA"
        );
        assert_eq!(archive.read("classes.dex").unwrap(), b"dex\n035\0");
    }

    #[test]
    fn align_and_sign_pure_preserves_16384_so_alignment() {
        let mut writer = ApkWriter::new();
        writer.add_entry("resources.arsc", b"ARSC_PAYLOAD", false);
        writer.add_entry("lib/arm64-v8a/libtest.so", b"\x7fELF_PAYLOAD", false);
        let raw_apk = writer.finish().unwrap();

        let signed = align_and_sign(&raw_apk, &SignOptions::default()).unwrap();
        let arsc_off = entry_data_offset(&signed, "resources.arsc").expect("resources.arsc present");
        let so_off =
            entry_data_offset(&signed, "lib/arm64-v8a/libtest.so").expect("libtest.so present");

        assert_eq!(arsc_off % 4, 0);
        assert_eq!(so_off % 16384, 0);
    }
}
