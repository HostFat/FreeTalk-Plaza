//! Shared types and rules for the image blob contract.
//!
//! One blob = one immutable payload addressed by its SHA-256. The parameters
//! name the content hash and the keys allowed to retire it; the state carries
//! the bytes, or the retirement proof once they are gone.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Hard safety bound enforced by the contract itself, independent of the board
/// limits: an image, or one chunk of a larger one, never exceeds this.
pub const MAX_BLOB_BYTES: usize = 8 * 1024 * 1024;

/// Payload pieces: a larger image is split into chunks of this size, each in
/// its own contract, and a manifest lists them.
pub const CHUNK_BYTES: usize = 1024 * 1024;

/// Upper bound on the chunks of one image. Twenty chunks cover the 20 MiB
/// animated ceiling.
pub const MAX_CHUNKS: usize = 20;

pub const MAX_DIMENSION: u32 = 20_000;

/// Mime types the client renders without plugins.
pub const ALLOWED_MIME_TYPES: [&str; 4] =
    ["image/jpeg", "image/png", "image/webp", "image/gif"];

/// Contract parameters: the content hash and the keys allowed to retire it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct BlobParametersV1 {
    pub sha256: [u8; 32],
    pub uploader: VerifyingKey,
    /// Founding owner of the board the image was uploaded to. A permanent
    /// emergency key, even after an ownership transfer.
    pub owner_founding: VerifyingKey,
    /// Owner of the board at the time of the upload.
    pub owner_current: VerifyingKey,
}

/// Contract state: the bytes, the chunk manifest, or the proof that they were
/// retired.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct BlobStateV1 {
    pub uploader: VerifyingKey,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    /// Payload of a single-contract blob. Empty for a manifest.
    pub data: Vec<u8>,
    /// Chunks of a larger payload. Empty for a single-contract blob. Both are
    /// skipped when empty so single-contract records keep their bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<ChunkRef>,
    /// Nonce of the symmetric seal, when the image belongs to a private board
    /// or a restricted section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<[u8; 12]>,
    /// Version of the secret used to seal the payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_version: Option<u32>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub retired: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retirement: Option<RetirementProof>,
}

/// One chunk of a larger payload, with the contract that holds it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ChunkRef {
    pub instance: [u8; 32],
    pub sha256: [u8; 32],
    pub bytes: u32,
}

/// What the manifest hash in the parameters covers.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct BlobManifestV1 {
    pub chunks: Vec<ChunkRef>,
}

/// Deterministic hash of a chunk list, used as the manifest contract's
/// content hash.
pub fn manifest_sha256(chunks: &[ChunkRef]) -> [u8; 32] {
    let manifest = BlobManifestV1 {
        chunks: chunks.to_vec(),
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&manifest, &mut bytes).expect("serializes");
    sha256(&bytes)
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Signed statement that the uploader or a board owner retired the blob.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct RetirementProof {
    pub signer: VerifyingKey,
    pub signature: Signature,
    /// Who the signer was: `uploader`, `owner-founding` or `owner-current`.
    pub role: RetirementRole,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum RetirementRole {
    Uploader,
    OwnerFounding,
    OwnerCurrent,
}

/// Payload covered by the retirement signature.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RetirementV1 {
    pub sha256: [u8; 32],
}

/// Digest of an image payload.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn sign_struct<T: Serialize>(value: &T, signer: &SigningKey) -> Signature {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).expect("serializes");
    signer.sign(&bytes)
}

fn verify_struct<T: Serialize>(
    value: &T,
    signature: &Signature,
    key: &VerifyingKey,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).map_err(|e| e.to_string())?;
    key.verify(&bytes, signature).map_err(|e| e.to_string())
}

impl BlobParametersV1 {
    pub fn new(
        sha256: [u8; 32],
        uploader: VerifyingKey,
        owner_founding: VerifyingKey,
        owner_current: VerifyingKey,
    ) -> Self {
        Self {
            sha256,
            uploader,
            owner_founding,
            owner_current,
        }
    }

    /// Which role, if any, this key holds for the blob.
    pub fn role_of(&self, key: &VerifyingKey) -> Option<RetirementRole> {
        if *key == self.uploader {
            Some(RetirementRole::Uploader)
        } else if *key == self.owner_founding {
            Some(RetirementRole::OwnerFounding)
        } else if *key == self.owner_current {
            Some(RetirementRole::OwnerCurrent)
        } else {
            None
        }
    }
}

impl BlobStateV1 {
    pub fn live(
        parameters: &BlobParametersV1,
        mime: String,
        width: u32,
        height: u32,
        data: Vec<u8>,
    ) -> Self {
        Self {
            uploader: parameters.uploader,
            mime,
            width,
            height,
            data,
            chunks: Vec::new(),
            nonce: None,
            secret_version: None,
            retired: false,
            retirement: None,
        }
    }

    /// Manifest state for a payload split into chunks.
    pub fn manifest(
        parameters: &BlobParametersV1,
        mime: String,
        width: u32,
        height: u32,
        chunks: Vec<ChunkRef>,
    ) -> Self {
        Self {
            uploader: parameters.uploader,
            mime,
            width,
            height,
            data: Vec::new(),
            chunks,
            nonce: None,
            secret_version: None,
            retired: false,
            retirement: None,
        }
    }

    /// Mark the payload as sealed with the board or section secret.
    pub fn sealed(mut self, nonce: [u8; 12], secret_version: u32) -> Self {
        self.nonce = Some(nonce);
        self.secret_version = Some(secret_version);
        self
    }

    /// Total stored bytes: the data itself or the sum of the chunks.
    pub fn stored_len(&self) -> usize {
        if self.chunks.is_empty() {
            self.data.len()
        } else {
            self.chunks.iter().map(|chunk| chunk.bytes as usize).sum()
        }
    }

    pub fn is_manifest(&self) -> bool {
        !self.chunks.is_empty()
    }

    pub fn validate(&self, parameters: &BlobParametersV1) -> Result<(), String> {
        if self.uploader != parameters.uploader {
            return Err("Blob uploader does not match the contract parameters".to_string());
        }
        if self.retired {
            let Some(proof) = self.retirement.as_ref() else {
                return Err("Retired blob has no retirement proof".to_string());
            };
            if !self.mime.is_empty() && !ALLOWED_MIME_TYPES.contains(&self.mime.as_str()) {
                return Err(format!("Retired blob mime type not allowed: {}", self.mime));
            }
            if !self.data.is_empty() || !self.chunks.is_empty() {
                return Err("Retired blob still carries content".to_string());
            }
            if self.nonce.is_some() || self.secret_version.is_some() {
                return Err("Retired blob still carries a seal".to_string());
            }
            let expected_role = parameters
                .role_of(&proof.signer)
                .ok_or("Retirement signer is not authorized for this blob")?;
            if proof.role != expected_role {
                return Err("Retirement role does not match the signer".to_string());
            }
            let payload = RetirementV1 {
                sha256: parameters.sha256,
            };
            verify_struct(&payload, &proof.signature, &proof.signer)?;
            return Ok(());
        }

        if self.retirement.is_some() {
            return Err("A live blob cannot carry a retirement proof".to_string());
        }
        if self.nonce.is_some() != self.secret_version.is_some() {
            return Err("A sealed blob needs both a nonce and a secret version".to_string());
        }
        if !ALLOWED_MIME_TYPES.contains(&self.mime.as_str()) {
            return Err(format!("Blob mime type not allowed: {}", self.mime));
        }
        if self.width == 0
            || self.height == 0
            || self.width > MAX_DIMENSION
            || self.height > MAX_DIMENSION
        {
            return Err(format!(
                "Blob dimensions {}x{} are not valid",
                self.width, self.height
            ));
        }

        if self.chunks.is_empty() {
            if self.data.is_empty() {
                return Err("Blob payload is empty".to_string());
            }
            if self.data.len() > MAX_BLOB_BYTES {
                return Err(format!(
                    "Blob payload {} exceeds the {} bytes limit",
                    self.data.len(),
                    MAX_BLOB_BYTES
                ));
            }
            if sha256(&self.data) != parameters.sha256 {
                return Err("Blob payload does not match the parameter hash".to_string());
            }
            return Ok(());
        }

        // A manifest carries no bytes of its own; the parameters hash covers
        // the canonical chunk list.
        if !self.data.is_empty() {
            return Err("A manifest cannot also carry payload bytes".to_string());
        }
        if self.chunks.len() > MAX_CHUNKS {
            return Err(format!(
                "Blob has {} chunks, the limit is {}",
                self.chunks.len(),
                MAX_CHUNKS
            ));
        }
        let mut seen = std::collections::HashSet::new();
        let mut total = 0usize;
        for chunk in &self.chunks {
            if chunk.instance == [0u8; 32] || chunk.sha256 == [0u8; 32] {
                return Err("A chunk needs a contract and a hash".to_string());
            }
            if chunk.bytes == 0 || chunk.bytes as usize > CHUNK_BYTES {
                return Err(format!(
                    "Chunk size {} is outside 1..={}",
                    chunk.bytes, CHUNK_BYTES
                ));
            }
            if !seen.insert(chunk.instance) {
                return Err("Duplicate chunk contract".to_string());
            }
            total += chunk.bytes as usize;
        }
        if total > MAX_BLOB_BYTES * MAX_CHUNKS {
            return Err("Chunk list is too large".to_string());
        }
        if manifest_sha256(&self.chunks) != parameters.sha256 {
            return Err("Chunk manifest does not match the parameter hash".to_string());
        }
        Ok(())
    }

    /// Build the retired state given the content hash and a signer whose role
    /// the caller knows. The contract verifies the role against its
    /// parameters; this is what lets a client retire a blob it did not upload
    /// without knowing the full parameter set.
    pub fn retired_by(
        template: &BlobStateV1,
        content_sha256: [u8; 32],
        signer: &SigningKey,
        role: RetirementRole,
    ) -> BlobStateV1 {
        let payload = RetirementV1 {
            sha256: content_sha256,
        };
        BlobStateV1 {
            uploader: template.uploader,
            mime: template.mime.clone(),
            width: template.width,
            height: template.height,
            data: Vec::new(),
            chunks: Vec::new(),
            nonce: None,
            secret_version: None,
            retired: true,
            retirement: Some(RetirementProof {
                signer: signer.verifying_key(),
                signature: sign_struct(&payload, signer),
                role,
            }),
        }
    }

    /// Build the retired state, signed by `signer`. Fails when the key is not
    /// allowed to retire this blob.
    pub fn retire(
        &self,
        parameters: &BlobParametersV1,
        signer: &SigningKey,
    ) -> Result<Self, String> {
        let key = signer.verifying_key();
        let role = parameters
            .role_of(&key)
            .ok_or("This key is not allowed to retire the blob")?;
        let payload = RetirementV1 {
            sha256: parameters.sha256,
        };
        Ok(Self {
            uploader: self.uploader,
            mime: self.mime.clone(),
            width: self.width,
            height: self.height,
            data: Vec::new(),
            chunks: Vec::new(),
            nonce: None,
            secret_version: None,
            retired: true,
            retirement: Some(RetirementProof {
                signer: key,
                signature: sign_struct(&payload, signer),
                role,
            }),
        })
    }
}

/// Merge an update into the current state. Retirement wins and is final: a
/// retired blob can never come back with content. Ties (both retired or both
/// live with differing metadata) are broken deterministically so merging is
/// commutative across peers.
pub fn merge_states(
    current: &BlobStateV1,
    incoming: &BlobStateV1,
    parameters: &BlobParametersV1,
) -> Result<BlobStateV1, String> {
    current.validate(parameters)?;
    incoming.validate(parameters)?;
    match (current.retired, incoming.retired) {
        (true, false) => Ok(current.clone()),
        (false, true) => Ok(incoming.clone()),
        _ => {
            if current == incoming {
                return Ok(current.clone());
            }
            let current_hash = canonical_blob_hash(current);
            let incoming_hash = canonical_blob_hash(incoming);
            if incoming_hash < current_hash {
                Ok(incoming.clone())
            } else {
                Ok(current.clone())
            }
        }
    }
}

fn canonical_blob_hash(state: &BlobStateV1) -> [u8; 32] {
    let mut bytes = Vec::new();
    let _ = ciborium::ser::into_writer(state, &mut bytes);
    sha256(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (SigningKey, SigningKey, SigningKey, SigningKey) {
        (
            SigningKey::from_bytes(&[1u8; 32]),
            SigningKey::from_bytes(&[2u8; 32]),
            SigningKey::from_bytes(&[3u8; 32]),
            SigningKey::from_bytes(&[4u8; 32]),
        )
    }

    fn setup() -> (BlobParametersV1, BlobStateV1, [SigningKey; 3]) {
        let (uploader, founding, current, _stranger) = keys();
        let data = b"fake image bytes".to_vec();
        let parameters = BlobParametersV1::new(
            sha256(&data),
            uploader.verifying_key(),
            founding.verifying_key(),
            current.verifying_key(),
        );
        let state = BlobStateV1::live(
            &parameters,
            "image/webp".to_string(),
            800,
            600,
            data,
        );
        (parameters, state, [uploader, founding, current])
    }

    #[test]
    fn a_live_blob_validates_and_a_wrong_hash_does_not() {
        let (parameters, state, _) = setup();
        state.validate(&parameters).expect("valid blob");

        let mut tampered = state.clone();
        tampered.data = b"other bytes".to_vec();
        assert!(tampered.validate(&parameters).is_err());

        let mut empty = state.clone();
        empty.data.clear();
        assert!(empty.validate(&parameters).is_err());
    }

    #[test]
    fn the_uploader_and_both_owners_can_retire_the_blob() {
        let (parameters, state, signers) = setup();
        for signer in signers {
            let retired = state.retire(&parameters, &signer).expect("retire");
            retired.validate(&parameters).expect("retired state verifies");
            assert!(retired.retired);
            assert!(retired.data.is_empty());
        }

        let (_, _, _, stranger) = keys();
        assert!(state.retire(&parameters, &stranger).is_err());
    }

    #[test]
    fn a_retirement_cannot_be_forged() {
        let (parameters, state, signers) = setup();
        let mut retired = state.retire(&parameters, &signers[0]).expect("retire");
        let proof = retired.retirement.as_mut().expect("proof");
        // Claim another role with the uploader's signature.
        proof.role = RetirementRole::OwnerFounding;
        assert!(retired.validate(&parameters).is_err());

        let mut restored = state.retire(&parameters, &signers[0]).expect("retire");
        restored.retirement = None;
        assert!(restored.validate(&parameters).is_err());
        restored.retirement = Some(RetirementProof {
            signer: signers[0].verifying_key(),
            signature: sign_struct(&RetirementV1 { sha256: [9u8; 32] }, &signers[0]),
            role: RetirementRole::Uploader,
        });
        assert!(restored.validate(&parameters).is_err());
    }

    #[test]
    fn retirement_wins_and_cannot_be_undone() {
        let (parameters, state, signers) = setup();
        let retired = state.retire(&parameters, &signers[0]).expect("retire");

        let merged = merge_states(&retired, &state, &parameters).expect("merge");
        assert!(merged.retired);
        assert!(merged.data.is_empty());

        let merged = merge_states(&state, &retired, &parameters).expect("merge");
        assert!(merged.retired);

        // A peer cannot bring a retired blob back to life.
        let mut revived = retired.clone();
        revived.retired = false;
        revived.data = state.data.clone();
        assert!(revived.validate(&parameters).is_err());
    }
    fn manifest_params(chunks: &[ChunkRef]) -> BlobParametersV1 {
        let (uploader, founding, current, _) = keys();
        BlobParametersV1::new(
            manifest_sha256(chunks),
            uploader.verifying_key(),
            founding.verifying_key(),
            current.verifying_key(),
        )
    }

    #[test]
    fn a_manifest_validates_and_checks_its_chunk_list() {
        let chunks = vec![
            ChunkRef {
                instance: [11u8; 32],
                sha256: [12u8; 32],
                bytes: CHUNK_BYTES as u32,
            },
            ChunkRef {
                instance: [21u8; 32],
                sha256: [22u8; 32],
                bytes: 500,
            },
        ];
        let parameters = manifest_params(&chunks);
        let state = BlobStateV1::manifest(
            &parameters,
            "image/webp".to_string(),
            800,
            600,
            chunks.clone(),
        );
        state.validate(&parameters).expect("a manifest passes");
        assert!(state.is_manifest());
        assert_eq!(state.stored_len(), CHUNK_BYTES + 500);

        // The parameter hash covers the chunk list.
        let mut other = parameters.clone();
        other.sha256 = [9u8; 32];
        assert!(state.validate(&other).is_err());

        let mut with_data = state.clone();
        with_data.data = b"extra".to_vec();
        assert!(with_data.validate(&parameters).is_err());

        let mut duplicated = chunks.clone();
        duplicated[1].instance = duplicated[0].instance;
        let duplicated_parameters = manifest_params(&duplicated);
        let duplicated_state = BlobStateV1::manifest(
            &duplicated_parameters,
            "image/webp".to_string(),
            800,
            600,
            duplicated,
        );
        assert!(duplicated_state.validate(&duplicated_parameters).is_err());

        let mut oversized = chunks.clone();
        oversized[0].bytes = (CHUNK_BYTES + 1) as u32;
        let oversized_parameters = manifest_params(&oversized);
        let oversized_state = BlobStateV1::manifest(
            &oversized_parameters,
            "image/webp".to_string(),
            800,
            600,
            oversized,
        );
        assert!(oversized_state.validate(&oversized_parameters).is_err());

        let mut empty_chunk = chunks.clone();
        empty_chunk[0].bytes = 0;
        let empty_parameters = manifest_params(&empty_chunk);
        let empty_state = BlobStateV1::manifest(
            &empty_parameters,
            "image/webp".to_string(),
            800,
            600,
            empty_chunk,
        );
        assert!(empty_state.validate(&empty_parameters).is_err());
    }

    #[test]
    fn a_sealed_blob_carries_a_nonce_and_a_version() {
        let (parameters, state, _) = setup();
        let sealed = state.clone().sealed([7u8; 12], 3);
        sealed.validate(&parameters).expect("a sealed blob passes");

        let mut half = sealed.clone();
        half.secret_version = None;
        assert!(half.validate(&parameters).is_err());
    }

    #[test]
    fn retiring_a_manifest_drops_the_chunks() {
        let chunks = vec![ChunkRef {
            instance: [31u8; 32],
            sha256: [32u8; 32],
            bytes: CHUNK_BYTES as u32,
        }];
        let parameters = manifest_params(&chunks);
        let state = BlobStateV1::manifest(
            &parameters,
            "image/webp".to_string(),
            800,
            600,
            chunks,
        );
        let (uploader, _, _, _) = keys();
        let retired = state.retire(&parameters, &uploader).expect("retire");
        retired.validate(&parameters).expect("retired manifest verifies");
        assert!(retired.chunks.is_empty());
        assert!(retired.nonce.is_none());
    }
    #[test]
    fn a_client_built_retirement_matches_the_contract_rules() {
        let (parameters, state, signers) = setup();
        let retired = BlobStateV1::retired_by(
            &state,
            parameters.sha256,
            &signers[0],
            RetirementRole::Uploader,
        );
        retired.validate(&parameters).expect("a valid retirement");
        assert!(retired.retired);
        assert!(retired.data.is_empty());

        let wrong_role = BlobStateV1::retired_by(
            &state,
            parameters.sha256,
            &signers[0],
            RetirementRole::OwnerCurrent,
        );
        assert!(wrong_role.validate(&parameters).is_err());
    }
    #[test]
    fn a_manifest_chunk_can_be_retired_by_an_owner() {
        let (uploader, founding, current, _) = keys();
        let chunk_data = vec![7u8; 1024];
        let parameters = BlobParametersV1::new(
            sha256(&chunk_data),
            uploader.verifying_key(),
            founding.verifying_key(),
            current.verifying_key(),
        );
        let state = BlobStateV1::live(
            &parameters,
            "image/webp".to_string(),
            10,
            10,
            chunk_data,
        );
        let retired = state.retire(&parameters, &current).expect("retire the chunk");
        retired
            .validate(&parameters)
            .expect("a retired chunk verifies");
        assert!(retired.retired);
        assert!(retired.data.is_empty());
    }
}

