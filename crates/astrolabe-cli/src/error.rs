//! Error handling and user-facing diagnostic formatting for Astrolabe CLI.

use astrolabe_core::AcfError;
use std::fmt;

/// CLI-level error type that preserves ACF error codes and provides actionable messages.
#[derive(Debug)]
#[allow(dead_code)]
pub enum CliError {
    /// An ACF specification error occurred.
    Acf(AcfError, String),
    /// File I/O error with file path context.
    Io(String, std::io::Error),
    /// JSON serialization/deserialization error with context.
    Json(String, serde_json::Error),
    /// Hex decoding error.
    Hex(String, hex::FromHexError),
    /// Command execution failure.
    CommandFailed(String, String),
    /// Missing required argument or option.
    MissingArgument(String),
    /// General error message.
    Other(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acf(code, msg) => write!(f, "[{}] {}", code.code(), msg),
            Self::Io(path, err) => write!(f, "Failed to read/write file '{}': {}", path, err),
            Self::Json(context, err) => write!(f, "JSON error in {}: {}", context, err),
            Self::Hex(context, err) => write!(f, "Invalid hex in {}: {}", context, err),
            Self::CommandFailed(cmd, details) => write!(f, "Command '{}' failed: {}", cmd, details),
            Self::MissingArgument(arg) => write!(f, "Missing required argument: {}", arg),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for CliError {}

impl From<AcfError> for CliError {
    fn from(err: AcfError) -> Self {
        let explanation = match err {
            AcfError::BadLength => "Payload length does not match expected size",
            AcfError::NonCanonicalField => "Coordinate or scalar is >= field modulus",
            AcfError::NotOnCurve => "Point does not satisfy the curve equation",
            AcfError::NotInSubgroup => "G2 point is not in the prime-order subgroup",
            AcfError::PublicInputCount => "Public-input count does not match verification key",
            AcfError::InvalidProof => "Degenerate point (infinity) or pairing check failed",
            AcfError::Unsupported => "Unsupported version, kind, curve, or system",
            AcfError::TrailingBytes => "Payload contains unexpected trailing bytes",
            AcfError::MalformedInput => "Input file could not be parsed as valid JSON/decimal",
        };
        Self::Acf(err, explanation.to_string())
    }
}
