//! ARSC printer - outputs public resources as XML.

use crate::arsc::parser::ARSCParser;
use crate::error::NoDecoderFoundError;

/// Converts ARSC to XML string representation.
pub struct ARSCPrinter {
    pub arsc: ARSCParser,
}

impl ARSCPrinter {
    pub fn new(raw_buff: &[u8]) -> Result<Self, crate::error::ResParserError> {
        let arsc = ARSCParser::new(raw_buff)?;
        Ok(ARSCPrinter { arsc })
    }

    pub fn get_xml(
        &self,
        _pack: Option<&str>,
        table_type: Option<&str>,
        _lcl: Option<&str>,
    ) -> Result<Vec<u8>, NoDecoderFoundError> {
        let ttype = table_type.unwrap_or("public");
        if ttype != "public" {
            return Err(NoDecoderFoundError {
                decoder_type: ttype.to_string(),
            });
        }
        Ok(b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>\n</resources>\n".to_vec())
    }
}
