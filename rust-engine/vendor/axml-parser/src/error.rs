//! Parser errors.

use std::fmt;

#[derive(Debug, Clone)]
pub struct ResParserError(pub String);

impl fmt::Display for ResParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ResParserError {}

#[derive(Debug, Clone)]
pub struct NoDecoderFoundError {
    pub decoder_type: String,
}

impl fmt::Display for NoDecoderFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "No decoder found for type: '{}'! Please open a bug report.",
            self.decoder_type
        )
    }
}

impl std::error::Error for NoDecoderFoundError {}
