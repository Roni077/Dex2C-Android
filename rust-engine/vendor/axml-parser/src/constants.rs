//! Constants for AXML/ARSC binary format.
//! See androidfw/ResourceTypes.h

// Chunk types
pub const RES_NULL_TYPE: u16 = 0x0000;
pub const RES_STRING_POOL_TYPE: u16 = 0x0001;
pub const RES_TABLE_TYPE: u16 = 0x0002;
pub const RES_XML_TYPE: u16 = 0x0003;

pub const RES_XML_FIRST_CHUNK_TYPE: u16 = 0x0100;
pub const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
pub const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
pub const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
pub const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
pub const RES_XML_CDATA_TYPE: u16 = 0x0104;
pub const RES_XML_LAST_CHUNK_TYPE: u16 = 0x017F;

pub const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;

pub const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
pub const RES_TABLE_TYPE_TYPE: u16 = 0x0201;
pub const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;
pub const RES_TABLE_LIBRARY_TYPE: u16 = 0x0203;
pub const RES_TABLE_OVERLAYABLE_TYPE: u16 = 0x0204;
pub const RES_TABLE_OVERLAYABLE_POLICY_TYPE: u16 = 0x0205;
pub const RES_TABLE_STAGED_ALIAS_TYPE: u16 = 0x0206;

// String pool flags
pub const SORTED_FLAG: u32 = 1 << 0;
pub const UTF8_FLAG: u32 = 1 << 8;

// Attribute indices (5 x 4 bytes per attribute)
pub const ATTRIBUTE_IX_NAMESPACE_URI: usize = 0;
pub const ATTRIBUTE_IX_NAME: usize = 1;
pub const ATTRIBUTE_IX_VALUE_STRING: usize = 2;
pub const ATTRIBUTE_IX_VALUE_TYPE: usize = 3;
pub const ATTRIBUTE_IX_VALUE_DATA: usize = 4;
pub const ATTRIBUTE_LENGTH: usize = 5;

// AXML parser event types
pub const START_DOCUMENT: i32 = 0;
pub const END_DOCUMENT: i32 = 1;
pub const START_TAG: i32 = 2;
pub const END_TAG: i32 = 3;
pub const TEXT: i32 = 4;

// Res_value data types
pub const TYPE_NULL: u8 = 0x00;
pub const TYPE_REFERENCE: u8 = 0x01;
pub const TYPE_ATTRIBUTE: u8 = 0x02;
pub const TYPE_STRING: u8 = 0x03;
pub const TYPE_FLOAT: u8 = 0x04;
pub const TYPE_DIMENSION: u8 = 0x05;
pub const TYPE_FRACTION: u8 = 0x06;
pub const TYPE_DYNAMIC_REFERENCE: u8 = 0x07;
pub const TYPE_DYNAMIC_ATTRIBUTE: u8 = 0x08;
pub const TYPE_FIRST_INT: u8 = 0x10;
pub const TYPE_INT_DEC: u8 = 0x10;
pub const TYPE_INT_HEX: u8 = 0x11;
pub const TYPE_INT_BOOLEAN: u8 = 0x12;
pub const TYPE_FIRST_COLOR_INT: u8 = 0x1C;
pub const TYPE_INT_COLOR_ARGB8: u8 = 0x1C;
pub const TYPE_INT_COLOR_RGB8: u8 = 0x1D;
pub const TYPE_INT_COLOR_ARGB4: u8 = 0x1E;
pub const TYPE_INT_COLOR_RGB4: u8 = 0x1F;
pub const TYPE_LAST_COLOR_INT: u8 = 0x1F;
pub const TYPE_LAST_INT: u8 = 0x1F;

// Dimension/fraction
pub const RADIX_MULTS: [f32; 4] = [0.00390625, 3.051758e-005, 1.192093e-007, 4.656613e-010];
pub const DIMENSION_UNITS: [&str; 8] = ["px", "dip", "sp", "pt", "in", "mm", "", ""];
pub const FRACTION_UNITS: [&str; 2] = ["%", "%p"];
pub const COMPLEX_UNIT_MASK: u32 = 0x0F;

// ARSC entry flags
pub const FLAG_COMPLEX: u16 = 1;
pub const FLAG_PUBLIC: u16 = 2;
pub const FLAG_WEAK: u16 = 4;
pub const FLAG_COMPACT: u16 = 8;
pub const FLAG_OFFSET16: u8 = 0x02;
pub const NO_ENTRY_16: u16 = 0xFFFF;
pub const NO_ENTRY_32: u32 = 0xFFFFFFFF;
