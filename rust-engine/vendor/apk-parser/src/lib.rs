//! APK parser - Rust port of apkparser (signature, zip, utils, permissions, manifest).

pub mod apk;
pub mod apkm;
pub mod dex_entries;
pub mod error;
pub mod manifest;
pub mod permissions;
pub mod signature;
pub mod utils;
pub mod zip;
pub mod zip64;

#[cfg(feature = "sign-pure")]
pub mod sign;
#[cfg(feature = "sign-pure")]
pub mod zip_write;

pub use apk::{Apk, ApkOptions};
pub use apkm::{looks_like_apkm, unwrap_to_apk_bytes, ApkmArchive, ApkmEntry, ApkmEntryKind};
pub use dex_entries::{dex_entries, iter_logical_dexes, logical_dex_offsets};
pub use error::{BrokenAPKError, Error, Result};
pub use manifest::{parse_manifest, AndroidManifest};
pub use permissions::{load_permissions, PermissionInfo, Permissions, PermissionsMap};
pub use signature::{
    parse_apk_sig_block, parse_apk_sig_block_at, ApkSignature, APK_SIG_KEY_V2_SIGNATURE,
    APK_SIG_KEY_V3_SIGNATURE,
};
pub use utils::{is_android, is_android_raw, read_uint32_le};
pub use zip::{
    CentralEntry, LocalMismatch, MethodUsed, ReadLimits, ReadOutcome, ZipArchive, ZipEntry,
    ZipIndex,
};

#[cfg(feature = "sign-pure")]
pub use sign::{
    align_and_sign, deserialize_debug_keystore, serialize_debug_keystore, sign_apk, zipalign,
    zipalign_page, zipalign_with_page_alignment, KeystoreMaterial, SignError, SignOptions,
    PAGE_ALIGNMENT,
};
#[cfg(feature = "sign-pure")]
pub use zip_write::{should_compress, ApkWriter, Compression};
