//! Client-side ML-KEM-768 for private board secrets.
//!
//! The contract only stores the opaque ciphertexts (`PqSecretsV1`). The KEM
//! key is derived from the board identity, so exporting or restoring the
//! Ed25519 identity restores the PQ key too. The seeded RNG keeps the wasm
//! build free of a second getrandom backend.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dioxus::prelude::*;
use ed25519_dalek::SigningKey;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use plaza_core::board_state::pq_secrets::{PqSealedSecret, PQ_KEM_CT_LEN, PQ_KEM_EK_LEN};
use sha2::{Digest, Sha512};

const KDF_CONTEXT: &[u8] = b"freetalk plaza pq board secret v1";

/// Derive the board's ML-KEM seed from its Ed25519 identity.
pub fn kem_seed(self_sk: &SigningKey) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(b"freetalk plaza pq kem seed v1");
    hasher.update(self_sk.to_bytes());
    let digest = hasher.finalize();
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&digest);
    seed
}

pub fn decapsulation_key(self_sk: &SigningKey) -> DecapsulationKey<MlKem768> {
    DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::from(kem_seed(self_sk)))
}

/// FIPS 203 encoded encapsulation key (1184 bytes).
pub fn encapsulation_key(self_sk: &SigningKey) -> Vec<u8> {
    decapsulation_key(self_sk)
        .encapsulation_key()
        .to_bytes()
        .to_vec()
}

/// Seal a 32-byte board/category secret to one member KEM key.
pub fn seal_secret(
    secret: &[u8; 32],
    ek_bytes: &[u8],
) -> Result<(Vec<u8>, [u8; 24], Vec<u8>), String> {
    if ek_bytes.len() != PQ_KEM_EK_LEN {
        return Err("Invalid ML-KEM encapsulation key length".to_string());
    }
    let ek_array = ml_kem::array::Array::try_from(ek_bytes)
        .map_err(|_| "Invalid ML-KEM encapsulation key".to_string())?;
    let ek = EncapsulationKey::<MlKem768>::new(&ek_array)
        .map_err(|_| "Invalid ML-KEM encapsulation key".to_string())?;
    let seed = crate::util::ecies::generate_board_secret();
    let mut rng = SeedRng::from_seed(seed);
    let (ciphertext, shared) = ek.encapsulate_with_rng(&mut rng);
    let key = blake3::derive_key(
        std::str::from_utf8(KDF_CONTEXT).expect("static context"),
        shared.as_slice(),
    );
    let nonce_bytes = crate::util::ecies::generate_board_secret();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes[..24]);
    let sealed = XChaCha20Poly1305::new((&key).into())
        .encrypt(XNonce::from_slice(&nonce), secret.as_slice())
        .map_err(|_| "Could not seal the PQ board secret".to_string())?;
    Ok((ciphertext.as_slice().to_vec(), nonce, sealed))
}

/// Open one sealed secret with this board identity.
pub fn open_secret(self_sk: &SigningKey, sealed: &PqSealedSecret) -> Result<[u8; 32], String> {
    if sealed.kem_ciphertext.len() != PQ_KEM_CT_LEN {
        return Err("Invalid ML-KEM ciphertext length".to_string());
    }
    let dk = decapsulation_key(self_sk);
    let shared = dk
        .decapsulate_slice(&sealed.kem_ciphertext)
        .map_err(|_| "Invalid ML-KEM ciphertext".to_string())?;
    let key = blake3::derive_key(
        std::str::from_utf8(KDF_CONTEXT).expect("static context"),
        shared.as_slice(),
    );
    let plaintext = XChaCha20Poly1305::new((&key).into())
        .decrypt(XNonce::from_slice(&sealed.nonce), sealed.sealed.as_slice())
        .map_err(|_| "Could not open the PQ board secret".to_string())?;
    if plaintext.len() != 32 {
        return Err("Unexpected PQ board secret length".to_string());
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&plaintext);
    Ok(secret)
}

/// Deterministic RNG for ML-KEM encapsulation, seeded from OS randomness.
struct SeedRng(u64);

impl SeedRng {
    fn from_seed(seed: [u8; 32]) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&seed[..8]);
        Self(u64::from_le_bytes(bytes) | 1)
    }
}

impl rand_core::TryRng for SeedRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        Ok(self.0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let value = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for SeedRng {}

/// Periodic client work on private boards: publish our KEM key, open the
/// board secret from a PQ set, and (as owner) seal it for members with keys.
pub fn housekeeping() {
    let Some(board_key) = crate::components::app::CURRENT_BOARD.read().owner_key else {
        return;
    };
    let mut changed = false;
    crate::components::app::BOARDS.with_mut(|boards| {
        let Some(board) = boards.map.get_mut(&board_key) else {
            return;
        };
        if !board.is_private() {
            return;
        }
        board.decrypt_pq_board_secrets();
        changed |= board.ensure_pq_key();
        changed |= board.generate_missing_pq_secrets();
    });
    if changed {
        crate::components::app::mark_needs_sync(board_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_roundtrips_from_the_identity() {
        let mut seed = [0u8; 32];
        seed[0] = 9;
        let sk = SigningKey::from_bytes(&seed);
        let ek = encapsulation_key(&sk);
        assert_eq!(ek.len(), PQ_KEM_EK_LEN);
        let secret = [42u8; 32];
        let (ciphertext, nonce, sealed) = seal_secret(&secret, &ek).unwrap();
        let record = PqSealedSecret {
            member_id: plaza_core::board_state::member::MemberId::from(&sk.verifying_key()),
            kem_ciphertext: ciphertext,
            nonce,
            sealed,
        };
        assert_eq!(open_secret(&sk, &record).unwrap(), secret);

        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert!(open_secret(&other, &record).is_err());
    }
}
