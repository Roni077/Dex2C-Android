//! ResTable_config parsing → Apktool-style directory qualifiers.

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::error::ResParserError;

/// Parsed `ResTable_config` with an Apktool-compatible qualifier suffix
/// (e.g. `hdpi`, `fr-rFR`, `v21`, or empty for default).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ARSCResTableConfig {
    pub size: u32,
    pub mcc: u16,
    pub mnc: u16,
    pub language: String,
    pub region: String,
    pub orientation: u8,
    pub touchscreen: u8,
    pub density: u16,
    pub keyboard: u8,
    pub navigation: u8,
    pub input_flags: u8,
    pub screen_width: u16,
    pub screen_height: u16,
    pub sdk_version: u16,
    pub screen_layout: u8,
    pub ui_mode: u8,
    pub smallest_width_dp: u16,
    pub screen_width_dp: u16,
    pub screen_height_dp: u16,
    pub screen_layout2: u8,
    pub color_mode: u8,
    /// Directory qualifier without leading `-` (empty = default config).
    pub qualifier: String,
}

impl ARSCResTableConfig {
    pub fn default_config() -> Self {
        Self::default()
    }

    pub fn is_default(&self) -> bool {
        self.qualifier.is_empty()
    }

    /// `values` or `values-<qualifiers>`.
    pub fn values_dir_name(&self) -> String {
        if self.qualifier.is_empty() {
            "values".into()
        } else {
            format!("values-{}", self.qualifier)
        }
    }
}

/// Read and consume a ResTable_config from the cursor; return parsed config.
pub fn parse_res_table_config(
    cursor: &mut Cursor<Vec<u8>>,
) -> Result<ARSCResTableConfig, ResParserError> {
    let start = cursor
        .stream_position()
        .map_err(|e| ResParserError(e.to_string()))?;
    let size = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ResParserError(format!("config size: {}", e)))?;
    let size = if size < 4 { 28 } else { size };

    let mut cfg = ARSCResTableConfig {
        size,
        ..Default::default()
    };

    if size >= 8 {
        cfg.mcc = cursor.read_u16::<LittleEndian>().unwrap_or(0);
        cfg.mnc = cursor.read_u16::<LittleEndian>().unwrap_or(0);
    }
    if size >= 12 {
        let mut lang = [0u8; 2];
        let mut region = [0u8; 2];
        let _ = cursor.read_exact(&mut lang);
        let _ = cursor.read_exact(&mut region);
        cfg.language = pack_language_or_region(&lang);
        cfg.region = pack_language_or_region(&region);
    }
    if size >= 16 {
        cfg.orientation = cursor.read_u8().unwrap_or(0);
        cfg.touchscreen = cursor.read_u8().unwrap_or(0);
        cfg.density = cursor.read_u16::<LittleEndian>().unwrap_or(0);
    }
    if size >= 20 {
        cfg.keyboard = cursor.read_u8().unwrap_or(0);
        cfg.navigation = cursor.read_u8().unwrap_or(0);
        cfg.input_flags = cursor.read_u8().unwrap_or(0);
        let _pad = cursor.read_u8().unwrap_or(0);
    }
    if size >= 24 {
        cfg.screen_width = cursor.read_u16::<LittleEndian>().unwrap_or(0);
        cfg.screen_height = cursor.read_u16::<LittleEndian>().unwrap_or(0);
    }
    if size >= 28 {
        cfg.sdk_version = cursor.read_u16::<LittleEndian>().unwrap_or(0);
        let _minor = cursor.read_u16::<LittleEndian>().unwrap_or(0);
    }
    if size >= 32 {
        cfg.screen_layout = cursor.read_u8().unwrap_or(0);
        cfg.ui_mode = cursor.read_u8().unwrap_or(0);
        cfg.smallest_width_dp = cursor.read_u16::<LittleEndian>().unwrap_or(0);
    }
    if size >= 36 {
        cfg.screen_width_dp = cursor.read_u16::<LittleEndian>().unwrap_or(0);
        cfg.screen_height_dp = cursor.read_u16::<LittleEndian>().unwrap_or(0);
    }
    // localeScript (4) + localeVariant (8) at 36..48 — skip for qualifier (language/region enough)
    if size >= 52 {
        let _ = cursor.seek(SeekFrom::Start(start + 48));
        cfg.screen_layout2 = cursor.read_u8().unwrap_or(0);
        cfg.color_mode = cursor.read_u8().unwrap_or(0);
    }

    cursor
        .seek(SeekFrom::Start(start + size as u64))
        .map_err(|e| ResParserError(e.to_string()))?;

    cfg.qualifier = build_qualifier(&cfg);
    Ok(cfg)
}

fn pack_language_or_region(bytes: &[u8; 2]) -> String {
    if bytes[0] == 0 && bytes[1] == 0 {
        return String::new();
    }
    // Packed 3-letter codes use high bit; common case is two ASCII letters.
    if bytes[0].is_ascii_alphabetic() && bytes[1].is_ascii_alphabetic() {
        return String::from_utf8_lossy(bytes).to_ascii_lowercase();
    }
    // Packed form (see AOSP ResTable_config):
    let first = bytes[0] as u16 | ((bytes[1] as u16) << 8);
    if first == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(3);
    out.push((((first >> 10) & 0x1f) as u8 + 0x60) as char);
    out.push((((first >> 5) & 0x1f) as u8 + 0x60) as char);
    out.push(((first & 0x1f) as u8 + 0x60) as char);
    out
}

fn build_qualifier(cfg: &ARSCResTableConfig) -> String {
    let mut parts: Vec<String> = Vec::new();

    if cfg.mcc != 0 {
        parts.push(format!("mcc{}", cfg.mcc));
        if cfg.mnc != 0 {
            parts.push(format!("mnc{:02}", cfg.mnc));
        }
    }
    if !cfg.language.is_empty() {
        if cfg.region.is_empty() {
            parts.push(cfg.language.clone());
        } else {
            parts.push(format!("{}-r{}", cfg.language, cfg.region.to_ascii_uppercase()));
        }
    }

    // layout direction (screenLayout2 bits)
    const MASK_LAYOUTDIR: u8 = 0xC0;
    const LAYOUTDIR_LTR: u8 = 0x40;
    const LAYOUTDIR_RTL: u8 = 0x80;
    match cfg.screen_layout2 & MASK_LAYOUTDIR {
        LAYOUTDIR_LTR => parts.push("ldltr".into()),
        LAYOUTDIR_RTL => parts.push("ldrtl".into()),
        _ => {}
    }

    if cfg.smallest_width_dp != 0 {
        parts.push(format!("sw{}dp", cfg.smallest_width_dp));
    }
    if cfg.screen_width_dp != 0 {
        parts.push(format!("w{}dp", cfg.screen_width_dp));
    }
    if cfg.screen_height_dp != 0 {
        parts.push(format!("h{}dp", cfg.screen_height_dp));
    }

    const MASK_SCREENSIZE: u8 = 0x0f;
    match cfg.screen_layout & MASK_SCREENSIZE {
        1 => parts.push("small".into()),
        2 => parts.push("normal".into()),
        3 => parts.push("large".into()),
        4 => parts.push("xlarge".into()),
        _ => {}
    }
    const MASK_SCREENLONG: u8 = 0x30;
    match cfg.screen_layout & MASK_SCREENLONG {
        0x10 => parts.push("notlong".into()),
        0x20 => parts.push("long".into()),
        _ => {}
    }
    const MASK_SCREENROUND: u8 = 0x03;
    match cfg.screen_layout2 & MASK_SCREENROUND {
        1 => parts.push("notround".into()),
        2 => parts.push("round".into()),
        _ => {}
    }

    const MASK_WIDE_COLOR: u8 = 0x03;
    match cfg.color_mode & MASK_WIDE_COLOR {
        1 => parts.push("nowidecg".into()),
        2 => parts.push("widecg".into()),
        _ => {}
    }
    const MASK_HDR: u8 = 0x0c;
    match cfg.color_mode & MASK_HDR {
        0x04 => parts.push("lowdr".into()),
        0x08 => parts.push("highdr".into()),
        _ => {}
    }

    match cfg.orientation {
        1 => parts.push("port".into()),
        2 => parts.push("land".into()),
        3 => parts.push("square".into()),
        _ => {}
    }

    const MASK_UI_MODE_TYPE: u8 = 0x0f;
    match cfg.ui_mode & MASK_UI_MODE_TYPE {
        2 => parts.push("desk".into()),
        3 => parts.push("car".into()),
        4 => parts.push("television".into()),
        5 => parts.push("appliance".into()),
        6 => parts.push("watch".into()),
        7 => parts.push("vrheadset".into()),
        _ => {}
    }
    const MASK_UI_MODE_NIGHT: u8 = 0x30;
    match cfg.ui_mode & MASK_UI_MODE_NIGHT {
        0x10 => parts.push("notnight".into()),
        0x20 => parts.push("night".into()),
        _ => {}
    }

    match cfg.density {
        0 => {}
        120 => parts.push("ldpi".into()),
        160 => parts.push("mdpi".into()),
        213 => parts.push("tvdpi".into()),
        240 => parts.push("hdpi".into()),
        320 => parts.push("xhdpi".into()),
        480 => parts.push("xxhdpi".into()),
        640 => parts.push("xxxhdpi".into()),
        0xffff => parts.push("nodpi".into()),
        0xfffe => parts.push("anydpi".into()),
        d => parts.push(format!("{d}dpi")),
    }

    match cfg.touchscreen {
        1 => parts.push("notouch".into()),
        3 => parts.push("finger".into()),
        _ => {}
    }

    const MASK_KEYSHIDDEN: u8 = 0x03;
    match cfg.input_flags & MASK_KEYSHIDDEN {
        1 => parts.push("keysexposed".into()),
        2 => parts.push("keyshidden".into()),
        3 => parts.push("keyssoft".into()),
        _ => {}
    }
    match cfg.keyboard {
        1 => parts.push("nokeys".into()),
        2 => parts.push("qwerty".into()),
        3 => parts.push("12key".into()),
        _ => {}
    }
    const MASK_NAVHIDDEN: u8 = 0x0c;
    match cfg.input_flags & MASK_NAVHIDDEN {
        0x04 => parts.push("navexposed".into()),
        0x08 => parts.push("navhidden".into()),
        _ => {}
    }
    match cfg.navigation {
        1 => parts.push("nonav".into()),
        2 => parts.push("dpad".into()),
        3 => parts.push("trackball".into()),
        4 => parts.push("wheel".into()),
        _ => {}
    }

    if cfg.screen_width != 0 && cfg.screen_height != 0 {
        parts.push(format!("{}x{}", cfg.screen_width, cfg.screen_height));
    }
    if cfg.sdk_version != 0 {
        parts.push(format!("v{}", cfg.sdk_version));
    }

    parts.join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_qualifier_empty() {
        let c = ARSCResTableConfig::default();
        assert!(c.qualifier.is_empty());
        assert_eq!(c.values_dir_name(), "values");
    }
}
