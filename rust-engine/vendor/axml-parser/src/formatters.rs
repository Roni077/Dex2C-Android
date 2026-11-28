//! Value formatting for ARSC/AXML attribute types.

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use std::io::Cursor;

use crate::constants::*;

/// Convert complex unit to float (dimension/fraction).
pub fn complex_to_float(xcomplex: u32) -> f32 {
    (f32::from_bits(xcomplex & 0xFFFFFF00)) * RADIX_MULTS[((xcomplex >> 4) & 3) as usize]
}

/// Format a value based on type and data.
pub fn format_value<F>(data_type: u8, data: u32, mut lookup_string: F) -> String
where
    F: FnMut(u32) -> String,
{
    let fmt_package = |x: u32| if x >> 24 == 1 { "android:" } else { "" }.to_string();
    let fmt_int = |x: u32| {
        if x > 0x7FFFFFFF {
            ((x & 0x7FFFFFFF) as i32).wrapping_sub(i32::MIN)
        } else {
            x as i32
        }
    };

    match data_type {
        TYPE_STRING => lookup_string(data),
        TYPE_ATTRIBUTE => format!("?{}{:08X}", fmt_package(data), data),
        TYPE_REFERENCE => format!("@{}{:08X}", fmt_package(data), data),
        TYPE_FLOAT => {
            let mut buf = [0u8; 4];
            byteorder::LittleEndian::write_u32(&mut buf, data);
            let f: f32 = Cursor::new(&buf).read_f32::<LittleEndian>().unwrap_or(0.0);
            format!("{}", f)
        }
        TYPE_INT_HEX => format!("0x{:08X}", data),
        TYPE_INT_BOOLEAN => {
            if data == 0 {
                "false".to_string()
            } else {
                "true".to_string()
            }
        }
        TYPE_DIMENSION => {
            let unit_idx = (data & COMPLEX_UNIT_MASK) as usize;
            let unit = DIMENSION_UNITS.get(unit_idx).copied().unwrap_or("");
            format!("{}{}", complex_to_float(data), unit)
        }
        TYPE_FRACTION => {
            let unit_idx = (data & COMPLEX_UNIT_MASK) as usize;
            let unit = FRACTION_UNITS.get(unit_idx).copied().unwrap_or("");
            format!("{}{}", complex_to_float(data) * 100.0, unit)
        }
        _ if (TYPE_FIRST_COLOR_INT..=TYPE_LAST_COLOR_INT).contains(&data_type) => {
            format!("#{:08X}", data)
        }
        _ if (TYPE_FIRST_INT..=TYPE_LAST_INT).contains(&data_type) => {
            format!("{}", fmt_int(data))
        }
        _ => format!("<0x{:X}, type 0x{:02X}>", data, data_type),
    }
}
