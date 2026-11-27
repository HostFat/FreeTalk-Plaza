use base64::{engine::general_purpose, Engine as _};
use data_encoding::BASE32;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Serialize a value to canonical CBOR bytes.
pub fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

/// Deserialize a CBOR byte slice into `T`.
pub fn decode_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    ciborium::de::from_reader(bytes).map_err(|error| error.to_string())
}

pub fn sign_struct<T: Serialize>(message: T, signing_key: &SigningKey) -> Signature {
    let data_to_sign = encode_cbor(&message).expect("Serialization should not fail");
    signing_key.sign(&data_to_sign)
}

pub fn verify_struct<T: Serialize>(
    message: &T,
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> Result<(), SignatureError> {
    let data_to_sign = encode_cbor(message).expect("Serialization should not fail");
    verifying_key.verify(&data_to_sign, signature)
}

pub fn truncated_base64<T: AsRef<[u8]>>(data: T) -> String {
    let encoded = general_purpose::STANDARD_NO_PAD.encode(data);
    encoded.chars().take(10).collect()
}

pub fn truncated_base32(bytes: &[u8]) -> String {
    let encoded = BASE32.encode(bytes);
    encoded.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_sign_verify_struct() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let message = "Hello, World!";
        let signature = sign_struct(message, &signing_key);
        assert!(verify_struct(&message, &signature, &verifying_key).is_ok());
    }
}
