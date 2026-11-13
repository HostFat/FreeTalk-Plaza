//! Client-side ML-KEM-768 for private board secrets.
//!
//! The contract only stores the opaque ciphertexts (`PqSecretsV1`). The KEM
//! key is derived from the board identity, so exporting or restoring the
//! Ed25519 identity restores the PQ key too. The seeded RNG keeps the wasm
//! build free of a second getrandom backend.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dioxus::prelude::*;
use ed25519_dalek::SigningKey;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::pq_secrets::{PqSealedSecret, PqSuite, PQ_KEM_CT_LEN, PQ_KEM_EK_LEN};
use sha2::{Digest, Sha512};

const KDF_CONTEXT: &[u8] = b"freetalk plaza pq board secret v1";

fn sealed_aad(member_id: &MemberId) -> Vec<u8> {
    let mut aad = b"freetalk-pq-secret-v2".to_vec();
    aad.extend_from_slice(member_id.as_bytes());
    aad
}

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

/// Seal a 32-byte secret with hybrid X25519 + ML-KEM-768.
pub fn seal_secret(
    secret: &[u8; 32],
    ek_bytes: &[u8],
    member_id: MemberId,
    recipient_vk: &ed25519_dalek::VerifyingKey,
) -> Result<PqSealedSecret, String> {
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
    if ek_bytes.len() != PQ_KEM_EK_LEN {
        return Err("Invalid ML-KEM encapsulation key length".to_string());
    }
    let ek_array = ml_kem::array::Array::try_from(ek_bytes)
        .map_err(|_| "Invalid ML-KEM encapsulation key".to_string())?;
    let ek = EncapsulationKey::<MlKem768>::new(&ek_array)
        .map_err(|_| "Invalid ML-KEM encapsulation key".to_string())?;

    // X25519 half of the hybrid: an ephemeral key against the member's
    // X25519 public key derived from their Ed25519 identity.
    let ephemeral_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let recipient_x25519 = crate::util::ecies::ed25519_to_x25519_public_key(recipient_vk);
    let x25519_shared = ephemeral_secret.diffie_hellman(&recipient_x25519);

    let mut rng = OsRngAdapter(rand::rngs::OsRng);
    let (ciphertext, kem_shared) = ek.encapsulate_with_rng(&mut rng);

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(x25519_shared.as_bytes());
    combined.extend_from_slice(kem_shared.as_slice());
    let key = blake3::derive_key(
        std::str::from_utf8(KDF_CONTEXT).expect("static context"),
        &combined,
    );
    let nonce_bytes = crate::util::ecies::generate_board_secret();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes[..24]);
    let sealed = XChaCha20Poly1305::new((&key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: secret.as_slice(),
                aad: &sealed_aad(&member_id),
            },
        )
        .map_err(|_| "Could not seal the PQ board secret".to_string())?;
    Ok(PqSealedSecret {
        member_id,
        kem_ciphertext: ciphertext.as_slice().to_vec(),
        nonce,
        sealed,
        suite: PqSuite::Hybrid,
        x25519_public: Some(ephemeral_public.to_bytes()),
    })
}

/// Open one sealed secret with this board identity.
pub fn open_secret(self_sk: &SigningKey, sealed: &PqSealedSecret) -> Result<[u8; 32], String> {
    if sealed.kem_ciphertext.len() != PQ_KEM_CT_LEN {
        return Err("Invalid ML-KEM ciphertext length".to_string());
    }
    let dk = decapsulation_key(self_sk);
    let kem_shared = dk
        .decapsulate_slice(&sealed.kem_ciphertext)
        .map_err(|_| "Invalid ML-KEM ciphertext".to_string())?;

    let combined = if matches!(sealed.suite, PqSuite::Hybrid) {
        let ephemeral = sealed
            .x25519_public
            .ok_or("Hybrid PQ secret is missing its X25519 key")?;
        let own_secret = crate::util::ecies::ed25519_to_x25519_private_key(self_sk);
        let x25519_shared = own_secret.diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral));
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(x25519_shared.as_bytes());
        combined.extend_from_slice(kem_shared.as_slice());
        combined
    } else {
        kem_shared.as_slice().to_vec()
    };
    let key = blake3::derive_key(
        std::str::from_utf8(KDF_CONTEXT).expect("static context"),
        &combined,
    );
    let plaintext = XChaCha20Poly1305::new((&key).into())
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload {
                msg: sealed.sealed.as_slice(),
                aad: &sealed_aad(&sealed.member_id),
            },
        )
        .map_err(|_| "Could not open the PQ board secret".to_string())?;
    if plaintext.len() != 32 {
        return Err("Unexpected PQ board secret length".to_string());
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&plaintext);
    Ok(secret)
}

/// Adapts `rand`'s OS-backed RNG to the `rand_core` 0.10 traits used by
/// ml-kem, so encapsulation uses the same cryptographic randomness as ECIES.
struct OsRngAdapter(rand::rngs::OsRng);

impl rand_core::TryRng for OsRngAdapter {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(rand::RngCore::next_u32(&mut self.0))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(rand::RngCore::next_u64(&mut self.0))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        rand::RngCore::fill_bytes(&mut self.0, dst);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for OsRngAdapter {}

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
        if !board.is_private() && board.restricted_categories().is_empty() {
            return;
        }
        board.decrypt_pq_board_secrets();
        changed |= board.ensure_pq_key();
        changed |= board.generate_missing_pq_secrets();
        changed |= board.generate_missing_pq_category_secrets();
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
        let member_id = MemberId::from(&sk.verifying_key());
        let record = seal_secret(&secret, &ek, member_id, &sk.verifying_key()).unwrap();
        assert_eq!(open_secret(&sk, &record).unwrap(), secret);

        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert!(open_secret(&other, &record).is_err());
    }
}
