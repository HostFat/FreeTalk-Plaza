//! Stable 256-bit identifiers derived with BLAKE3.
//!
//! The previous `FastHash` ids were a 64-bit polynomial hash. They are replaced
//! wholesale; boards created before this change are not compatible.

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoardId(pub [u8; 32]);

impl BoardId {
    pub fn hash(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for BoardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", BASE32_NOPAD.encode(&self.0))
    }
}

impl fmt::Debug for BoardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BoardId({})", self)
    }
}

impl FromStr for BoardId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = BASE32_NOPAD
            .decode(value.as_bytes())
            .map_err(|error| format!("Invalid board id: {error}"))?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "A board id must be 32 bytes".to_string())?;
        Ok(Self(array))
    }
}
