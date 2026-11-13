//! Shared helpers for the post-quantum cost spike.

use ciborium::ser::into_writer;
use serde::Serialize;

pub const MESSAGE_BYTES: usize = 500;
pub const MEMBERS: usize = 10;

#[derive(Serialize)]
pub struct SpikeState {
    pub members: Vec<MemberRecord>,
    pub messages: Vec<MessageRecord>,
}

#[derive(Serialize)]
pub struct MemberRecord {
    pub id: u64,
    pub verifying_key: Vec<u8>,
}

#[derive(Serialize)]
pub struct MessageRecord {
    pub author: u64,
    pub time: u64,
    pub content: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn state_bytes(state: &SpikeState) -> usize {
    let mut bytes = Vec::new();
    into_writer(state, &mut bytes).expect("CBOR");
    bytes.len()
}

pub fn content() -> Vec<u8> {
    vec![b'x'; MESSAGE_BYTES]
}

/// Exercise the Ed25519 path so it is kept in the wasm build.
#[no_mangle]
pub extern "C" fn ed25519_probe(seed: u32) -> u32 {
    use ed25519_dalek::{Signer, Verifier};
    let mut sk_bytes = [0u8; 32];
    sk_bytes[..4].copy_from_slice(&seed.to_le_bytes());
    let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
    let msg = content();
    let sig = sk.sign(&msg);
    let ok = sk.verifying_key().verify(&msg, &sig).is_ok();
    (ok as u32) + sig.to_bytes().len() as u32
}

/// Deterministic RNG for the wasm probe. The native benchmark uses fresh
/// seeds from the OS; the KEM ciphertext itself is what we measure.
#[cfg(feature = "pq")]
struct FixedRng(u64);

#[cfg(feature = "pq")]
impl rand_core::TryRng for FixedRng {
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
#[cfg(feature = "pq")]
impl rand_core::TryCryptoRng for FixedRng {}

#[cfg(feature = "pq")]
#[no_mangle]
pub extern "C" fn pq_probe(seed: u32) -> u32 {
    use ml_dsa::signature::{Keypair, Signer, Verifier};
    use ml_dsa::{EncodedVerifyingKey, MlDsa65, Seed, SigningKey, VerifyingKey};
    use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
    use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};

    let mut dsa_seed = [0u8; 32];
    dsa_seed[..4].copy_from_slice(&seed.to_le_bytes());
    let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from(dsa_seed));
    let msg = content();
    let sig = Signer::sign(&sk, &msg);
    let vk_bytes = sk.verifying_key().encode();
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(vk_bytes.as_slice()).expect("vk");
    let vk = VerifyingKey::<MlDsa65>::decode(&encoded);
    let dsa_ok = vk.verify(&msg, &sig).is_ok();

    let kem_seed = ml_kem::Seed::from([seed as u8; 64]);
    let dk = DecapsulationKey::<MlKem768>::from_seed(kem_seed);
    let ek_bytes = dk.encapsulation_key().to_bytes();
    let ek = EncapsulationKey::<MlKem768>::new(&ek_bytes).expect("ek");
    let (ct, shared) = ek.encapsulate_with_rng(&mut FixedRng(0x9e3779b97f4a7c15));
    let recovered = dk.decapsulate(&ct);
    let kem_ok = recovered == shared;

    (dsa_ok as u32) + (kem_ok as u32) + sig.encode().len() as u32
}
