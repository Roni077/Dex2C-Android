//! Pure-Rust APK alignment (`16384`-byte `.so`, `4`-byte `resources.arsc`) and
//! v2/v3 APK Signature Scheme signer backed by `apkparser::sign`.

use apkparser::{
    sign_apk, zipalign_with_page_alignment, KeystoreMaterial, SignOptions, PAGE_ALIGNMENT,
};

/// ASN.1 DER OID `1.2.840.10045.2.1` (`ecPublicKey`), present inside PKCS#8 EC private keys.
const EC_PUBLIC_KEY_OID_DER: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// Re-aligns ZIP entries (`so_page_alignment` bytes for `.so`, 4 bytes for other stored
/// entries) and applies APK Signature Scheme v2 / v3 (plus optional v1 JAR) without `ring`/`rcgen`.
///
/// When `private_key_der` or `certificate_der` is empty/None, falls back to the embedded
/// Android Debug RSA-2048 keystore (`KeystoreMaterial::debug()`).
pub fn align_and_sign_apk_bytes(
    apk_bytes: &[u8],
    private_key_der: Option<&[u8]>,
    certificate_der: Option<&[u8]>,
    enable_v1: bool,
    enable_v2: bool,
    enable_v3: bool,
    so_page_alignment: u32,
) -> Result<Vec<u8>, String> {
    if apk_bytes.len() < 22 {
        return Err("APK buffer is too short to be a valid ZIP archive".to_string());
    }

    let keystore = match (private_key_der, certificate_der) {
        (Some(pk), Some(cert)) if !pk.is_empty() && !cert.is_empty() => {
            let is_ec = pk.windows(EC_PUBLIC_KEY_OID_DER.len()).any(|w| w == EC_PUBLIC_KEY_OID_DER);
            KeystoreMaterial {
                private_key_der: pk.to_vec(),
                certificate_der: cert.to_vec(),
                is_ec,
            }
        }
        _ => KeystoreMaterial::debug(),
    };

    let align = if so_page_alignment == 0 {
        PAGE_ALIGNMENT
    } else {
        so_page_alignment
    };

    let aligned = zipalign_with_page_alignment(apk_bytes, align)
        .map_err(|e| format!("zipalign failed: {e}"))?;

    let options = SignOptions {
        v1: enable_v1,
        v2: enable_v2,
        v3: enable_v3,
        keystore,
    };

    sign_apk(&aligned, &options).map_err(|e| format!("sign_apk failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use apkparser::signature::ApkSignature;
    use std::io::Write;
    use zip::write::FileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn entry_data_offset(apk: &[u8], target_name: &str) -> Option<usize> {
        let eocd = (0..=apk.len().saturating_sub(22))
            .rev()
            .find(|&pos| apk.get(pos..pos + 4) == Some(&[0x50, 0x4b, 0x05, 0x06]))?;
        let cd_off = u32::from_le_bytes(apk[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        // Note: cd_off sits *after* the APK Signing Block, while LFHs precede the Signing Block.
        let mut pos = 0usize;
        while pos + 30 <= cd_off && pos + 30 <= apk.len() {
            if apk[pos..pos + 4] != [0x50, 0x4b, 0x03, 0x04] {
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
    fn test_align_and_sign_v2_v3_with_16kb_so_alignment_and_deflated_entries() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zw = ZipWriter::new(&mut cursor);
            let stored = FileOptions::default().compression_method(CompressionMethod::Stored);
            let deflated = FileOptions::default().compression_method(CompressionMethod::Deflated);

            zw.start_file("resources.arsc", stored).unwrap();
            zw.write_all(b"ARSC_TEST_PAYLOAD").unwrap();
            zw.start_file("lib/arm64-v8a/libnative.so", stored).unwrap();
            zw.write_all(b"\x7fELF_FAKE_NATIVE_SO").unwrap();
            zw.start_file("classes.dex", deflated).unwrap();
            zw.write_all(b"dex\n039\0_COMPRESSED_PAYLOAD_FOR_SIGNER_TEST").unwrap();
            zw.finish().unwrap();
        }
        let unsigned_apk = cursor.into_inner();

        let signed = align_and_sign_apk_bytes(
            &unsigned_apk,
            None,
            None,
            false,
            true,
            true,
            PAGE_ALIGNMENT,
        )
        .expect("sign APK v2+v3");

        let so_offset = entry_data_offset(&signed, "lib/arm64-v8a/libnative.so").expect(".so present");
        let arsc_offset = entry_data_offset(&signed, "resources.arsc").expect("arsc present");
        assert_eq!(so_offset % 16384, 0, ".so must be 16KB aligned (got {so_offset})");
        assert_eq!(arsc_offset % 4, 0, "resources.arsc must be 4-byte aligned (got {arsc_offset})");

        let mut sig = ApkSignature::from_bytes(&signed).expect("parse APK signature block");
        assert!(!sig.is_signed_v1());
        assert!(sig.is_signed_v2());
        assert!(sig.is_signed_v3());
        assert_eq!(sig.get_certificates_der_v2().unwrap().len(), 1);
        assert_eq!(sig.get_certificates_der_v3().unwrap().len(), 1);
    }
}
