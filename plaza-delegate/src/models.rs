use super::*;

// Disjoint keyspace tags under each attested origin:
// - Data keys:    "{origin_b58}:k:{hex(key)}"
// - Key index:    "{origin_b58}:idx"
// - Signing keys: "signing_key:{origin_b58}:{board_key_b58}"
pub(crate) const DATA_KEY_TAG: &str = ":k:";
pub(crate) const INDEX_KEY_TAG: &str = ":idx";

/// Origin contract ID - represents the attested identity of the caller
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Origin(pub(crate) Vec<u8>);

impl Origin {
    pub(crate) fn to_b58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }
}
