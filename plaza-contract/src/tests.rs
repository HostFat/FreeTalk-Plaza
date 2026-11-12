//! Contract-level invariant tests.
//!
//! These call the trait methods directly (no node): `validate_state` must
//! refuse a state that `apply_delta`'s cleanup would rewrite, otherwise every
//! peer publishes a slightly different state and anti-entropy heals forever.

#[cfg(test)]
mod tests {
    use crate::Contract;
    use ciborium::ser::into_writer;
    use ed25519_dalek::SigningKey;
    use freenet_stdlib::prelude::{ContractInterface, Parameters, RelatedContracts, State};
    use plaza_core::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use plaza_core::board_state::member::{AuthorizedMember, Member};
    use plaza_core::board_state::ChatBoardParametersV1;
    use plaza_core::ChatBoardStateV1;

    fn parameters(owner: &SigningKey) -> Parameters<'static> {
        let mut bytes = Vec::new();
        into_writer(
            &ChatBoardParametersV1 {
                owner: owner.verifying_key(),
            },
            &mut bytes,
        )
        .unwrap();
        Parameters::from(bytes)
    }

    fn state_bytes(state: &ChatBoardStateV1) -> State<'static> {
        let mut bytes = Vec::new();
        into_writer(state, &mut bytes).unwrap();
        State::from(bytes)
    }

    /// Deterministic signing key: the contract crate builds ed25519-dalek
    /// without the `rand_core` feature.
    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A board with a member who has written nothing must be pruned, so the
    /// state as given is not a fixpoint and must be rejected.
    #[test]
    fn validate_state_rejects_a_state_cleanup_would_change() {
        let owner = key(1);
        let owner_params = ChatBoardParametersV1 {
            owner: owner.verifying_key(),
        };
        let owner_id = owner_params.owner_id();

        let member_key = key(2);
        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner),
            ..Default::default()
        };
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: member_key.verifying_key(),
            },
            &owner,
        ));

        let params = parameters(&owner);
        let result = <Contract as ContractInterface>::validate_state(
            params.clone(),
            state_bytes(&state),
            RelatedContracts::default(),
        );
        assert!(
            result.is_err(),
            "a state cleanup would rewrite must be rejected, not stored"
        );

        let mut normalized = state;
        normalized.normalize(&owner_params).unwrap();
        assert!(
            <Contract as ContractInterface>::validate_state(
                params,
                state_bytes(&normalized),
                RelatedContracts::default(),
            )
            .is_ok(),
            "the normalized state must be accepted"
        );
    }
}
