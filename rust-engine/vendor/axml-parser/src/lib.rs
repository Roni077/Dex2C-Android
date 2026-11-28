//! Android binary XML (AXML) and resource (ARSC) parser in pure Rust.
//!
//! Port of [androguard/axml](https://github.com/androguard/axml) Python library.

pub mod constants;
pub mod error;
pub mod formatters;
pub mod header;
pub mod public;
pub mod stringblock;

pub mod axml {
    pub mod encode;
    pub mod parser;
    pub mod printer;
}

pub mod arsc {
    pub mod builder;
    pub mod config;
    pub mod parser;
    pub mod printer;
}

pub use arsc::builder::{
    build_arsc, encode_string_pool, ArscBuildConfig, ArscBuildEntry, ArscBuildInput, ArscBuildType,
    ArscBuildValue,
};
pub use arsc::config::ARSCResTableConfig;
pub use arsc::parser::{
    ARSCParser, ArscBag, ArscBagItem, ArscResourceEntry, OverlayableGroup, OverlayablePolicy,
};
pub use arsc::printer::ARSCPrinter;
pub use axml::encode::encode_xml;
pub use axml::parser::AXMLParser;
pub use axml::printer::AXMLPrinter;
pub use error::{NoDecoderFoundError, ResParserError};
pub use header::ARSCHeader;
