use ed25519_dalek::{SigningKey, VerifyingKey};
use plaza_core::board_state::member::MemberId;
use std::collections::HashSet;
use std::str::FromStr;

#[cfg(test)]
mod id_tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn member_ids_are_blake3_derived_and_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let member_id: MemberId = verifying_key.into();

        assert_eq!(member_id.as_bytes().len(), 32);
        assert_eq!(
            member_id.as_bytes(),
            blake3::hash(verifying_key.as_bytes()).as_bytes()
        );

        let display = format!("{}", member_id);
        assert_eq!(MemberId::from_str(&display).unwrap(), member_id);
    }

    #[test]
    fn display_strings_are_unique_at_forum_scale() {
        let mut display_ids = HashSet::new();
        for _ in 0..10_000 {
            let signing_key = SigningKey::generate(&mut OsRng);
            let member_id: MemberId = signing_key.verifying_key().into();
            assert!(
                display_ids.insert(format!("{}", member_id)),
                "two member ids rendered the same display string"
            );
        }
    }
}
