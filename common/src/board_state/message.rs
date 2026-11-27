use crate::board_state::id::BoardId;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Eq, PartialEq, Hash, Serialize, Deserialize, Copy, Clone, Ord, PartialOrd)]
pub struct MessageId(pub BoardId);

impl MessageId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(BoardId::from_bytes(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", self.0)
    }
}

impl std::str::FromStr for MessageId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(value.parse::<BoardId>()?))
    }
}
