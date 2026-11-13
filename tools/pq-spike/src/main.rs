use std::hint::black_box;
use std::time::Instant;

use ed25519_dalek::{Signer as _, Verifier as _};
use pq_spike::{content, state_bytes, MemberRecord, MessageRecord, SpikeState, MEMBERS};

#[cfg(feature = "pq")]
use ml_dsa::signature::{Keypair, Signer as _, Verifier as _};
#[cfg(feature = "pq")]
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Seed, SigningKey, VerifyingKey};
#[cfg(feature = "pq")]
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
#[cfg(feature = "pq")]
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};

const SIZES: [usize; 3] = [100, 1_000, 10_000];

#[derive(Clone)]
struct EdMember {
    signing: ed25519_dalek::SigningKey,
    verifying: Vec<u8>,
    id: u64,
}

#[cfg(feature = "pq")]
#[derive(Clone)]
struct PqMember {
    signing: SigningKey<MlDsa65>,
    verifying: Vec<u8>,
    id: u64,
}

fn ed_members() -> Vec<EdMember> {
    (0..MEMBERS)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
            EdMember {
                verifying: signing.verifying_key().to_bytes().to_vec(),
                signing,
                id: i as u64,
            }
        })
        .collect()
}

#[cfg(feature = "pq")]
fn pq_members() -> Vec<PqMember> {
    (0..MEMBERS)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let signing = SigningKey::<MlDsa65>::from_seed(&Seed::from(seed));
            PqMember {
                verifying: signing.verifying_key().encode().to_vec(),
                signing,
                id: i as u64,
            }
        })
        .collect()
}

fn print_header() {
    println!("records    ed_state    pq_state    ed_sign    pq_sign    ed_verify    pq_verify");
    println!("           (bytes)     (bytes)     (ms)       (ms)       (ms)         (ms)");
}

fn main() {
    let content = content();
    let ed = ed_members();
    #[cfg(feature = "pq")]
    let pq = pq_members();

    println!("message payload: {} bytes", content.len());
    println!("members: {}", MEMBERS);
    println!();
    print_header();

    for &n in &SIZES {
        let ed_start = Instant::now();
        let ed_signed: Vec<(u64, Vec<u8>)> = (0..n)
            .map(|i| {
                let member = &ed[i % ed.len()];
                let sig = member.signing.sign(&content).to_bytes().to_vec();
                (member.id, sig)
            })
            .collect();
        let ed_sign = ed_start.elapsed().as_secs_f64() * 1000.0;

        let ed_state = SpikeState {
            members: ed
                .iter()
                .map(|m| MemberRecord {
                    id: m.id,
                    verifying_key: m.verifying.clone(),
                })
                .collect(),
            messages: ed_signed
                .iter()
                .map(|(author, signature)| MessageRecord {
                    author: *author,
                    time: 1,
                    content: content.clone(),
                    signature: signature.clone(),
                })
                .collect(),
        };
        let ed_state_bytes = state_bytes(&ed_state);

        let ed_verify_start = Instant::now();
        let mut ed_ok = 0usize;
        for (author, signature) in &ed_signed {
            let member = ed.iter().find(|m| m.id == *author).expect("member");
            let sig = ed25519_dalek::Signature::from_slice(signature).expect("sig");
            if member
                .signing
                .verifying_key()
                .verify(black_box(&content), &sig)
                .is_ok()
            {
                ed_ok += 1;
            }
        }
        let ed_verify = ed_verify_start.elapsed().as_secs_f64() * 1000.0;
        black_box(ed_ok);

        #[cfg(feature = "pq")]
        {
            let pq_start = Instant::now();
            let pq_signed: Vec<(u64, Vec<u8>)> = (0..n)
                .map(|i| {
                    let member = &pq[i % pq.len()];
                    let sig: ml_dsa::Signature<MlDsa65> =
                        ml_dsa::signature::Signer::sign(&member.signing, &content);
                    (member.id, sig.encode().to_vec())
                })
                .collect();
            let pq_sign = pq_start.elapsed().as_secs_f64() * 1000.0;

            let pq_state = SpikeState {
                members: pq
                    .iter()
                    .map(|m| MemberRecord {
                        id: m.id,
                        verifying_key: m.verifying.clone(),
                    })
                    .collect(),
                messages: pq_signed
                    .iter()
                    .map(|(author, signature)| MessageRecord {
                        author: *author,
                        time: 1,
                        content: content.clone(),
                        signature: signature.clone(),
                    })
                    .collect(),
            };
            let pq_state_bytes = state_bytes(&pq_state);

            let pq_verify_start = Instant::now();
            let mut pq_ok = 0usize;
            for (author, signature) in &pq_signed {
                let member = pq.iter().find(|m| m.id == *author).expect("member");
                let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(member.verifying.as_slice())
                    .expect("vk");
                let vk = VerifyingKey::<MlDsa65>::decode(&encoded);
                let sig =
                    ml_dsa::Signature::<MlDsa65>::try_from(signature.as_slice()).expect("sig");
                if vk.verify(black_box(&content), &sig).is_ok() {
                    pq_ok += 1;
                }
            }
            let pq_verify = pq_verify_start.elapsed().as_secs_f64() * 1000.0;
            black_box(pq_ok);

            println!(
                "{:<10} {:>10} {:>11} {:>9.1} {:>10.1} {:>11.1} {:>12.1}",
                n, ed_state_bytes, pq_state_bytes, ed_sign, pq_sign, ed_verify, pq_verify
            );
        }

        #[cfg(not(feature = "pq"))]
        println!(
            "{:<10} {:>10} {:>11} {:>9.1} {:>10} {:>11.1} {:>12}",
            n, ed_state_bytes, "-", ed_sign, "-", ed_verify, "-"
        );
    }

    println!();
    println!("ed25519 verifying key: {} bytes", ed[0].verifying.len());
    println!("ed25519 signature: 64 bytes");

    #[cfg(feature = "pq")]
    {
        println!("ml-dsa-65 verifying key: {} bytes", pq[0].verifying.len());
        let sig_len = {
            let sig: ml_dsa::Signature<MlDsa65> =
                ml_dsa::signature::Signer::sign(&pq[0].signing, &content);
            sig.encode().len()
        };
        println!("ml-dsa-65 signature: {} bytes", sig_len);

        let seed = ml_kem::Seed::from([7u8; 64]);
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        let ek_bytes = dk.encapsulation_key().to_bytes();
        let ek = EncapsulationKey::<MlKem768>::new(&ek_bytes).expect("ek");

        let encaps_start = Instant::now();
        for _ in 0..1_000 {
            let (ct, shared) = ek.encapsulate_with_rng(&mut FixedRng(0x1234_5678_9abc_def0));
            black_box(ct);
            black_box(shared);
        }
        let encaps = encaps_start.elapsed().as_secs_f64() * 1000.0 / 1_000.0;

        let (ct, shared) = ek.encapsulate_with_rng(&mut FixedRng(0x1234_5678_9abc_def0));
        let decaps_start = Instant::now();
        for _ in 0..1_000 {
            black_box(dk.decapsulate(&ct));
        }
        let decaps = decaps_start.elapsed().as_secs_f64() * 1000.0 / 1_000.0;
        black_box(shared);

        println!("ml-kem-768 encapsulation key: {} bytes", ek_bytes.len());
        println!("ml-kem-768 ciphertext: {} bytes", ct.len());
        println!(
            "ml-kem-768 encaps/decaps: {:.3} ms / {:.3} ms",
            encaps, decaps
        );
        println!(
            "sealed secret blob (nonce24 + ct + tag16): {} bytes",
            24 + 1088 + 32 + 16
        );
        println!(
            "x25519 sealed secret blob (ephemeral32 + nonce12 + tag16): {} bytes",
            32 + 12 + 32 + 16
        );
    }
}

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
