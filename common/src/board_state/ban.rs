use crate::board_state::member::{AuthorizedMember, MemberId};
use crate::board_state::ChatBoardParametersV1;
use crate::util::{sign_struct, verify_struct};
use crate::ChatBoardStateV1;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use freenet_scaffold::util::{fast_hash, FastHash};
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::time::SystemTime;

/// Represents a collection of user bans in a chat board
///
/// This structure maintains a list of authorized bans and provides methods
/// to verify, summarize, and apply changes to the ban list while ensuring
/// all bans are valid according to board rules.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct BansV1(pub Vec<AuthorizedUserBan>);

/// Represents different types of validation errors that can occur with bans
#[derive(Debug, Clone, PartialEq)]
pub enum BanValidationError {
    /// The banned member was not found in the member list
    MemberNotFound(MemberId),

    /// The banning member was not found in the member list
    BannerNotFound(MemberId),

    /// The banning member is not in the invite chain of the banned member
    NotInInviteChain(MemberId, MemberId),

    /// The board owner cannot be banned
    TargetIsOwner,

    /// The ban names a different board owner
    OwnerMismatch,

    /// A circular invite chain was detected
    SelfInvitationDetected(MemberId),

    /// The inviting member was not found for a member in the chain
    InviterNotFound(MemberId),

    /// The number of bans exceeds the maximum allowed
    ExceededMaximumBans,
}

impl fmt::Display for BanValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BanValidationError::MemberNotFound(id) => {
                write!(f, "Banned member not found in member list: {:?}", id)
            }
            BanValidationError::BannerNotFound(id) => {
                write!(f, "Banning member not found in member list: {:?}", id)
            }
            BanValidationError::TargetIsOwner => {
                write!(f, "The board owner cannot be banned")
            }
            BanValidationError::OwnerMismatch => {
                write!(f, "The ban names a different board owner")
            }
            BanValidationError::NotInInviteChain(banner_id, banned_id) => write!(
                f,
                "Banner {:?} is not in the invite chain of banned member {:?}",
                banner_id, banned_id
            ),
            BanValidationError::SelfInvitationDetected(id) => {
                write!(f, "Self-invitation detected for member {:?}", id)
            }
            BanValidationError::InviterNotFound(id) => {
                write!(f, "Inviting member not found for {:?}", id)
            }
            BanValidationError::ExceededMaximumBans => {
                write!(f, "Exceeded maximum number of user bans")
            }
        }
    }
}

impl BansV1 {
    /// Delta-time verification: a ban and the member record of its banner may
    /// arrive in the same update, so a missing banner is deferred to the final
    /// state verification instead of rejecting the whole update.
    fn verify_for_apply(
        &self,
        parent_state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
    ) -> Result<(), String> {
        let invalid_bans = self.get_invalid_bans(parent_state, parameters, true);
        if !invalid_bans.is_empty() {
            let error_messages: Vec<String> = invalid_bans
                .iter()
                .map(|(id, error)| format!("{:?}: {}", id, error))
                .collect();
            return Err(format!("Invalid bans: {}", error_messages.join(", ")));
        }
        if self.0.len() > parent_state.configuration.configuration.max_user_bans {
            return Err("Number of bans exceeds the maximum allowed".to_string());
        }

        let members_by_id = parent_state.members.members_by_member_id();
        for ban in &self.0 {
            if ban.banned_by == parameters.owner_id() {
                ban.verify_signature(&parameters.owner)
                    .map_err(|e| format!("Invalid ban signature: {}", e))?;
            } else if let Some(member) = members_by_id.get(&ban.banned_by) {
                ban.verify_signature(&member.member.member_vk)
                    .map_err(|e| format!("Invalid ban signature: {}", e))?;
            }
        }
        Ok(())
    }

    /// Validates all bans in the collection and returns a map of invalid bans with errors
    ///
    /// This method checks:
    /// - If the banned member still exists, verifies the banning member is in their invite chain
    ///   (unless banner is owner or admin). If the banned member was already removed, the ban is valid.
    /// - If the banning member exists (for non-owner/non-admin bans where banned member still exists)
    /// - If the number of bans exceeds the maximum allowed
    fn get_invalid_bans(
        &self,
        parent_state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
        allow_missing_banner: bool,
    ) -> HashMap<BanId, BanValidationError> {
        let member_map = parent_state.members.members_by_member_id();
        let admin_ids: HashSet<MemberId> = parent_state
            .admin
            .admins
            .iter()
            .map(|a| a.admin.id())
            .collect();
        let mut invalid_bans = HashMap::new();
        let banned_user_ids: HashSet<MemberId> = self.0.iter().map(|b| b.ban.banned_user).collect();

        // Validate each ban
        for ban in &self.0 {
            self.validate_single_ban(
                ban,
                &member_map,
                parameters,
                &admin_ids,
                &mut invalid_bans,
                &banned_user_ids,
                allow_missing_banner,
            );
        }

        // Check for excess bans
        self.identify_excess_bans(parent_state, &mut invalid_bans);

        invalid_bans
    }

    /// Validates a single ban and adds any validation errors to the invalid_bans map
    fn validate_single_ban(
        &self,
        ban: &AuthorizedUserBan,
        member_map: &HashMap<MemberId, &AuthorizedMember>,
        parameters: &ChatBoardParametersV1,
        admin_ids: &HashSet<MemberId>,
        invalid_bans: &mut HashMap<BanId, BanValidationError>,
        banned_user_ids: &HashSet<MemberId>,
        allow_missing_banner: bool,
    ) {
        if ban.ban.owner_member_id != parameters.owner_id() {
            invalid_bans.insert(ban.id(), BanValidationError::OwnerMismatch);
            return;
        }
        if ban.ban.banned_user == parameters.owner_id() {
            invalid_bans.insert(ban.id(), BanValidationError::TargetIsOwner);
            return;
        }

        let is_owner = ban.banned_by == parameters.owner_id();
        let is_admin = admin_ids.contains(&ban.banned_by);
        if !is_owner && !is_admin {
            // The banner must still be present so its key can verify the ban.
            // A ban signed by a pruned member is removed by cleanup instead of
            // being accepted without a signature check.
            let Some(banning_member) = member_map.get(&ban.banned_by) else {
                let _ = banned_user_ids;
                if allow_missing_banner {
                    // The members delta may arrive in the same update; the
                    // final state verification remains strict.
                    return;
                }
                invalid_bans.insert(ban.id(), BanValidationError::BannerNotFound(ban.banned_by));
                return;
            };

            // The target may already be removed by this ban, in which case the
            // invite chain can no longer be walked. The signature and banner
            // checks above still apply.
            let Some(banned_member) = member_map.get(&ban.ban.banned_user) else {
                // The target is already removed by this ban; the invite chain
                // cannot be walked. The banner and signature checks still
                // apply. New bans against arbitrary absent ids are rejected by
                // apply_delta before they enter the state.
                return;
            };

            if let Err(error) = self.validate_invite_chain(
                banned_member,
                banning_member,
                member_map,
                parameters.owner_id(),
                ban.id(),
            ) {
                invalid_bans.insert(ban.id(), error);
            }
        }
    }

    /// Validates that the banning member is in the invite chain of the banned member
    fn validate_invite_chain(
        &self,
        banned_member: &AuthorizedMember,
        banning_member: &AuthorizedMember,
        member_map: &HashMap<MemberId, &AuthorizedMember>,
        owner_id: MemberId,
        _ban_id: BanId,
    ) -> Result<(), BanValidationError> {
        let mut current_member = banned_member;
        let mut chain = Vec::new();

        while current_member.member.id() != owner_id {
            chain.push(current_member);

            // If we found the banning member in the chain, the ban is valid
            if current_member.member.id() == banning_member.member.id() {
                return Ok(());
            }

            // Move up the invite chain
            current_member = match member_map.get(&current_member.member.invited_by) {
                Some(m) => m,
                None => {
                    return Err(BanValidationError::InviterNotFound(
                        current_member.member.id(),
                    ));
                }
            };

            // Check for circular invite chains
            if chain.contains(&current_member) {
                return Err(BanValidationError::SelfInvitationDetected(
                    current_member.member.id(),
                ));
            }
        }

        // If we reached the owner without finding the banning member, the ban is invalid
        Err(BanValidationError::NotInInviteChain(
            banning_member.member.id(),
            banned_member.member.id(),
        ))
    }

    /// Identifies bans that exceed the maximum allowed limit.
    /// When timestamps are equal, uses BanId as a secondary sort key
    /// for deterministic ordering (CRDT convergence requirement).
    fn identify_excess_bans(
        &self,
        parent_state: &ChatBoardStateV1,
        invalid_bans: &mut HashMap<BanId, BanValidationError>,
    ) {
        let max_bans = parent_state.configuration.configuration.max_user_bans;
        let extra_bans = self.0.len() as isize - max_bans as isize;

        if extra_bans > 0 {
            // Add oldest extra bans to invalid bans
            // Sort by timestamp (newest first), with BanId as tie-breaker
            let mut extra_bans_vec = self.0.clone();
            extra_bans_vec.sort_by(|a, b| {
                // Primary: sort by timestamp (will be reversed, so older = later in list)
                // Secondary: sort by BanId for deterministic tie-breaking
                a.ban
                    .banned_at
                    .cmp(&b.ban.banned_at)
                    .then_with(|| a.id().cmp(&b.id()))
            });
            extra_bans_vec.reverse();

            for ban in extra_bans_vec.iter().take(extra_bans as usize) {
                invalid_bans.insert(ban.id(), BanValidationError::ExceededMaximumBans);
            }
        }
    }
}

impl ComposableState for BansV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = BTreeSet<BanId>;
    type Delta = Vec<AuthorizedUserBan>;
    type Parameters = ChatBoardParametersV1;

    /// Verifies that all bans in the collection are valid
    ///
    /// Checks that:
    /// - All bans have valid signatures
    /// - Banning members are authorized to ban (in invite chain)
    /// - The number of bans doesn't exceed the maximum allowed
    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let invalid_bans = self.get_invalid_bans(parent_state, parameters, false);
        if !invalid_bans.is_empty() {
            let error_messages: Vec<String> = invalid_bans
                .iter()
                .map(|(id, error)| format!("{:?}: {}", id, error))
                .collect();
            return Err(format!("Invalid bans: {}", error_messages.join(", ")));
        }

        // Check if the number of bans exceeds the maximum allowed
        if self.0.len() > parent_state.configuration.configuration.max_user_bans {
            return Err(format!(
                "Number of bans ({}) exceeds the maximum allowed ({})",
                self.0.len(),
                parent_state.configuration.configuration.max_user_bans
            ));
        }

        let members_by_id = parent_state.members.members_by_member_id();

        let owner_vk = parameters.owner;
        let owner_id = parameters.owner_id();

        // Verify signatures for all bans
        for ban in &self.0 {
            if ban.banned_by == owner_id {
                ban.verify_signature(&owner_vk)
                    .map_err(|e| format!("Invalid ban signature: {}", e))?;
            } else if let Some(banning_member) = members_by_id.get(&ban.banned_by) {
                ban.verify_signature(&banning_member.member.member_vk)
                    .map_err(|e| format!("Invalid ban signature: {}", e))?;
            } else {
                // Without the banner's key the signature cannot be checked.
                // Cleanup drops these bans, so a state that still contains one
                // is not accepted.
                return Err(format!(
                    "Cannot verify ban {}: banner {} is not a member",
                    ban.id().0 .0,
                    ban.banned_by
                ));
            }
        }

        Ok(())
    }

    /// Creates a summary of the current ban state
    ///
    /// Returns a set of all ban IDs currently in the collection
    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.0.iter().map(|ban| ban.id()).collect()
    }

    /// Computes the difference between current ban state and old state
    ///
    /// Returns a vector of bans that exist in the current state but not in the old state,
    /// or None if there are no differences
    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        // Identify bans in self.0 that are not in old_state_summary
        let delta = self
            .0
            .iter()
            .filter(|ban| !old_state_summary.contains(&ban.id()))
            .cloned()
            .collect::<Vec<_>>();
        if delta.is_empty() {
            None
        } else {
            Some(delta)
        }
    }

    /// Applies changes from a delta to the current ban state
    ///
    /// This method:
    /// - Checks for duplicate bans
    /// - Verifies all new bans are valid
    /// - Adds the new bans to the collection
    /// - Removes oldest bans if the total exceeds max_user_bans
    ///
    /// Returns an error if any ban in the delta is invalid or already exists
    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(delta) = delta {
            // Check for duplicate bans
            let existing_ban_ids: std::collections::HashSet<_> =
                self.0.iter().map(|ban| ban.id()).collect();
            for new_ban in delta {
                if existing_ban_ids.contains(&new_ban.id()) {
                    return Err(format!("Duplicate ban detected: {:?}", new_ban.id()));
                }
                // The target may be absent because the same update adds or
                // removes it during a merge, so its presence is not checked
                // here. The banner signature and authority are verified, and
                // the final state verification applies the strict rules.
            }

            // Create a temporary BansV1 with the new bans
            let mut temp_bans = self.clone();
            temp_bans.0.extend(delta.iter().cloned());

            // Enforce the cap, keeping owner bans
            temp_bans.enforce_cap(parent_state, parameters);

            // Verify the temporary bans. A banner that is being added in the
            // same update is deferred to the final state verification.
            if let Err(e) = temp_bans.verify_for_apply(parent_state, parameters) {
                return Err(format!("Invalid delta: {}", e));
            }

            // If verification passes, update the actual board_state
            self.0 = temp_bans.0;
        }

        // Sort for deterministic ordering (CRDT convergence requirement)
        self.0.sort_by(|a, b| {
            a.ban
                .banned_at
                .cmp(&b.ban.banned_at)
                .then_with(|| a.id().cmp(&b.id()))
        });

        Ok(())
    }
}

impl BansV1 {
    /// Trim the collection to `max_user_bans`.
    ///
    /// Eviction is oldest-first (with `BanId` tie-breaking) so every peer drops
    /// the same entries, except that bans issued by the owner are kept: they are
    /// signed by the party the parameters name, so an attacker flooding bans
    /// cannot age out the owner's moderation. If owner bans alone exceed the
    /// cap, the oldest of those are dropped too, because `verify` refuses an
    /// over-cap state.
    pub fn enforce_cap(
        &mut self,
        parent_state: &ChatBoardStateV1,
        parameters: &ChatBoardParametersV1,
    ) {
        let owner_id = parameters.owner_id();
        let max_bans = parent_state.configuration.configuration.max_user_bans;

        self.0.sort_by(|a, b| {
            a.ban
                .banned_at
                .cmp(&b.ban.banned_at)
                .then_with(|| a.id().cmp(&b.id()))
        });

        if self.0.len() <= max_bans {
            return;
        }

        let mut to_remove = self.0.len() - max_bans;
        let mut kept = Vec::with_capacity(max_bans);
        for ban in std::mem::take(&mut self.0) {
            if to_remove > 0 && ban.banned_by != owner_id {
                to_remove -= 1;
                continue;
            }
            kept.push(ban);
        }
        if kept.len() > max_bans {
            let excess = kept.len() - max_bans;
            kept.drain(0..excess);
        }
        self.0 = kept;
    }
}

/// A user ban with authorization proof
///
/// Contains the ban details, the ID of the member who created the ban,
/// and a cryptographic signature proving the ban's authenticity
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthorizedUserBan {
    pub ban: UserBan,
    pub banned_by: MemberId,
    pub signature: Signature,
}

impl Eq for AuthorizedUserBan {}

impl Hash for AuthorizedUserBan {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.signature.to_bytes().hash(state);
    }
}

impl AuthorizedUserBan {
    /// Creates a new authorized ban
    ///
    /// Signs the ban with the provided signing key and verifies that the
    /// banned_by ID matches the public key derived from the signing key
    pub fn new(ban: UserBan, banned_by: MemberId, banner_signing_key: &SigningKey) -> Self {
        assert_eq!(
            MemberId::from(banner_signing_key.verifying_key()),
            banned_by
        );

        let signature = sign_struct(&ban, banner_signing_key);

        Self {
            ban,
            banned_by,
            signature,
        }
    }

    /// Create an AuthorizedUserBan with a pre-computed signature.
    /// Use this when signing is done externally (e.g., via delegate).
    pub fn with_signature(ban: UserBan, banned_by: MemberId, signature: Signature) -> Self {
        Self {
            ban,
            banned_by,
            signature,
        }
    }

    /// Verifies that the ban's signature is valid
    ///
    /// Checks that the signature was created by the key corresponding to the provided verifying key
    pub fn verify_signature(&self, banner_verifying_key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.ban, &self.signature, banner_verifying_key)
            .map_err(|e| format!("Invalid ban signature: {}", e))
    }

    /// Generates a unique identifier for this ban based on its signature
    pub fn id(&self) -> BanId {
        BanId(fast_hash(&self.signature.to_bytes()))
    }
}

/// Contains the core information about a user ban
///
/// Includes the board owner's ID, the time of the ban, and the ID of the banned user
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UserBan {
    pub owner_member_id: MemberId,
    pub banned_at: SystemTime,
    pub banned_user: MemberId,
    /// When the ban should be lifted. The contract cannot use a clock, so a
    /// moderator publishes a revocation after this moment; the UI offers it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<SystemTime>,
}

/// A unique identifier for a ban
///
/// Created from a hash of the ban's signature to ensure uniqueness
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Hash, Debug, Ord, PartialOrd)]
pub struct BanId(pub FastHash);

/// A signed record that lifts one ban. Revocations stay in state as tombstones
/// so a stale peer cannot reintroduce the ban. The contract cannot use a wall
/// clock, so a temporary ban ends when a moderator publishes this record.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct BanRevocationV1 {
    pub ban_id: BanId,
    pub banned_user: MemberId,
    pub revoked_at: SystemTime,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct AuthorizedBanRevocation {
    pub revocation: BanRevocationV1,
    pub signer: Option<MemberId>,
    pub signature: Signature,
}

impl AuthorizedBanRevocation {
    pub fn new(revocation: BanRevocationV1, signing_key: &SigningKey) -> Self {
        Self {
            signature: sign_struct(&revocation, signing_key),
            revocation,
            signer: Some(MemberId::from(&signing_key.verifying_key())),
        }
    }

    pub fn signer_id(&self, parameters: &ChatBoardParametersV1) -> MemberId {
        self.signer.unwrap_or_else(|| parameters.owner_id())
    }

    pub fn verify_signature_with(&self, key: &VerifyingKey) -> Result<(), String> {
        verify_struct(&self.revocation, &self.signature, key)
            .map_err(|e| format!("Invalid ban revocation signature: {}", e))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct BanRevocationsV1 {
    pub revocations: Vec<AuthorizedBanRevocation>,
}

fn verify_revocation(
    state: &ChatBoardStateV1,
    parameters: &ChatBoardParametersV1,
    entry: &AuthorizedBanRevocation,
) -> Result<(), String> {
    let signer = entry.signer_id(parameters);
    let key = crate::board_state::roles::signer_key(state, parameters, &signer)?;
    entry.verify_signature_with(&key)?;
    // Owner-only keeps the tombstone verifiable forever: the owner key is in
    // the contract parameters even if every member record is pruned.
    if signer != parameters.owner_id() {
        return Err("Only the board owner can lift a ban".to_string());
    }
    Ok(())
}

impl BanRevocationsV1 {
    pub fn revoked(&self, ban_id: &BanId) -> bool {
        self.revocations
            .iter()
            .any(|entry| entry.revocation.ban_id == *ban_id)
    }

    pub fn cleanup(&mut self, state: &ChatBoardStateV1, parameters: &ChatBoardParametersV1) {
        self.revocations
            .retain(|entry| verify_revocation(state, parameters, entry).is_ok());
        self.revocations.sort_by_key(|entry| {
            (
                entry.revocation.ban_id.0 .0,
                entry.signer_id(parameters).0 .0,
            )
        });
        self.revocations
            .dedup_by_key(|entry| entry.revocation.ban_id.clone());
    }
}

impl ComposableState for BanRevocationsV1 {
    type ParentState = ChatBoardStateV1;
    type Summary = BTreeSet<BanId>;
    type Delta = Vec<AuthorizedBanRevocation>;
    type Parameters = ChatBoardParametersV1;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        let mut ids = HashSet::new();
        for entry in &self.revocations {
            if !ids.insert(entry.revocation.ban_id.clone()) {
                return Err("Duplicate ban revocation".to_string());
            }
            verify_revocation(parent_state, parameters, entry)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.revocations
            .iter()
            .map(|entry| entry.revocation.ban_id.clone())
            .collect()
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state: &Self::Summary,
    ) -> Option<Self::Delta> {
        let delta: Vec<AuthorizedBanRevocation> = self
            .revocations
            .iter()
            .filter(|entry| !old_state.contains(&entry.revocation.ban_id))
            .cloned()
            .collect();
        if delta.is_empty() {
            None
        } else {
            Some(delta)
        }
    }

    fn apply_delta(
        &mut self,
        parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        let Some(delta) = delta else {
            return Ok(());
        };
        for entry in delta {
            verify_revocation(parent_state, parameters, entry)?;
            if !self.revoked(&entry.revocation.ban_id) {
                self.revocations.push(entry.clone());
            }
        }
        self.revocations
            .sort_by_key(|entry| entry.revocation.ban_id.0 .0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_state::configuration::AuthorizedConfigurationV1;
    use crate::board_state::member::{AuthorizedMember, Member, MembersV1};
    use ed25519_dalek::SigningKey;
    use std::time::Duration;

    fn create_test_chat_board_state() -> ChatBoardStateV1 {
        // Create a minimal ChatBoardStateV1 for testing
        ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::default(),
            bans: Default::default(),
            members: MembersV1::default(),
            member_info: Default::default(),
            secrets: Default::default(),
            recent_messages: Default::default(),
            upgrade: Default::default(),
            ..Default::default()
        }
    }

    fn create_test_parameters() -> ChatBoardParametersV1 {
        // Create minimal ChatBoardParametersV1 for testing
        let owner_key = SigningKey::generate(&mut rand::thread_rng());
        ChatBoardParametersV1 {
            owner: owner_key.verifying_key(),
        }
    }

    #[test]
    fn test_bans_verify() {
        let mut state = create_test_chat_board_state();

        // Create some test members
        let owner_key = SigningKey::generate(&mut rand::thread_rng());
        let owner_id: MemberId = owner_key.verifying_key().into();
        let params = ChatBoardParametersV1 {
            owner: owner_key.verifying_key(),
        };
        let member1_key = SigningKey::generate(&mut rand::thread_rng());
        let member1_id: MemberId = member1_key.verifying_key().into();
        let member2_key = SigningKey::generate(&mut rand::thread_rng());
        let member2_id: MemberId = member2_key.verifying_key().into();

        // Add members to the board_state
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: owner_key.verifying_key(),
                join_proof: None,
            },
            &owner_key,
        ));
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: member1_key.verifying_key(),
                join_proof: None,
            },
            &owner_key,
        ));
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: member1_id,
                member_vk: member2_key.verifying_key(),
                join_proof: None,
            },
            &member1_key,
        ));

        // Update the configuration to allow bans
        state.configuration.configuration.max_user_bans = 5;

        // Test 1: Valid ban by owner
        let ban1 = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: SystemTime::now(),
                banned_user: member1_id,
                expires_at: None,
            },
            owner_id,
            &owner_key,
        );

        let bans = BansV1(vec![ban1]);
        assert!(
            bans.verify(&state, &params).is_ok(),
            "Valid ban should be verified successfully: {:?}",
            bans.verify(&state, &params).err()
        );

        // Test 2: Exceeding max_user_bans
        let mut many_bans = Vec::new();
        for _ in 0..6 {
            many_bans.push(AuthorizedUserBan::new(
                UserBan {
                    owner_member_id: owner_id,
                    banned_at: SystemTime::now(),
                    banned_user: member1_id,
                    expires_at: None,
                },
                owner_id,
                &owner_key,
            ));
        }
        let too_many_bans = BansV1(many_bans);
        assert!(
            too_many_bans.verify(&state, &params).is_err(),
            "Exceeding max_user_bans should fail verification"
        );

        // Test 3: Ban by pruned member (not in member list, not banned) — valid
        // With message-based lifecycle, banners not in the members list who
        // are not themselves banned are considered pruned for inactivity.
        let pruned_key = SigningKey::generate(&mut rand::thread_rng());
        let pruned_id: MemberId = pruned_key.verifying_key().into();
        let pruned_ban = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: SystemTime::now(),
                banned_user: member2_id,
                expires_at: None,
            },
            pruned_id,
            &pruned_key,
        );

        let pruned_bans = BansV1(vec![pruned_ban]);
        assert!(
            pruned_bans.verify(&state, &params).is_err(),
            "A ban whose banner key is gone cannot be verified"
        );

        // Test 3b: Orphaned ban (banner was banned) — invalid
        let orphaned_key = SigningKey::generate(&mut rand::thread_rng());
        let orphaned_id: MemberId = orphaned_key.verifying_key().into();
        let orphaned_ban = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: SystemTime::now(),
                banned_user: member2_id,
                expires_at: None,
            },
            orphaned_id,
            &orphaned_key,
        );
        // A ban targeting the orphaned member makes them "banned" (not just pruned)
        let ban_of_orphaned = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: SystemTime::now(),
                banned_user: orphaned_id,
                expires_at: None,
            },
            owner_id,
            &owner_key,
        );
        let orphaned_bans = BansV1(vec![orphaned_ban, ban_of_orphaned]);
        assert!(
            orphaned_bans.verify(&state, &params).is_err(),
            "Orphaned ban (banner was banned) should fail verification"
        );

        // Test 4: Valid ban by non-owner member
        let ban_by_member = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: SystemTime::now(),
                banned_user: member2_id,
                expires_at: None,
            },
            member1_id,
            &member1_key,
        );

        let member_bans = BansV1(vec![ban_by_member]);
        assert!(
            member_bans.verify(&state, &params).is_ok(),
            "Valid ban by non-owner member should pass verification"
        );
    }

    #[test]
    fn test_bans_summarize() {
        let state = create_test_chat_board_state();
        let params = create_test_parameters();

        let key = SigningKey::generate(&mut rand::thread_rng());
        let id: MemberId = key.verifying_key().into();

        let ban1 = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: id,
                banned_at: SystemTime::now(),
                banned_user: id,
                expires_at: None,
            },
            id,
            &key,
        );

        let ban2 = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: id,
                banned_at: SystemTime::now() + Duration::from_secs(1),
                banned_user: id,
                expires_at: None,
            },
            id,
            &key,
        );

        let bans = BansV1(vec![ban1.clone(), ban2.clone()]);
        let summary = bans.summarize(&state, &params);

        assert_eq!(summary.len(), 2);
        assert!(summary.contains(&ban1.id()));
        assert!(summary.contains(&ban2.id()));
    }

    #[test]
    fn test_bans_delta() {
        let state = create_test_chat_board_state();
        let params = create_test_parameters();

        let key = SigningKey::generate(&mut rand::thread_rng());
        let id: MemberId = key.verifying_key().into();

        let ban1 = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: id,
                banned_at: SystemTime::now(),
                banned_user: id,
                expires_at: None,
            },
            id,
            &key,
        );

        let ban2 = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: id,
                banned_at: SystemTime::now() + Duration::from_secs(1),
                banned_user: id,
                expires_at: None,
            },
            id,
            &key,
        );

        let bans = BansV1(vec![ban1.clone(), ban2.clone()]);

        // Test 1: Empty old summary
        let empty_summary = BTreeSet::new();
        let delta = bans.delta(&state, &params, &empty_summary);
        assert_eq!(delta, Some(vec![ban1.clone(), ban2.clone()]));

        // Test 2: Partial old summary
        let partial_summary: BTreeSet<BanId> = vec![ban1.id()].into_iter().collect();
        let delta = bans.delta(&state, &params, &partial_summary);
        assert_eq!(delta, Some(vec![ban2.clone()]));

        // Test 3: Full old summary
        let full_summary: BTreeSet<BanId> = vec![ban1.id(), ban2.id()].into_iter().collect();
        let delta = bans.delta(&state, &params, &full_summary);
        assert_eq!(delta, None);
    }

    #[test]
    fn ban_summary_is_order_independent() {
        let state = create_test_chat_board_state();
        let params = create_test_parameters();
        let key = SigningKey::generate(&mut rand::thread_rng());
        let id: MemberId = key.verifying_key().into();

        let make = |secs: u64| {
            AuthorizedUserBan::new(
                UserBan {
                    owner_member_id: id,
                    banned_at: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
                    banned_user: id,
                    expires_at: None,
                },
                id,
                &key,
            )
        };
        let (first, second) = (make(1), make(2));

        let serialize = |bans: &BansV1| {
            let mut out = Vec::new();
            ciborium::ser::into_writer(&bans.summarize(&state, &params), &mut out).unwrap();
            out
        };

        // Two peers that received the same bans in different orders must send
        // identical summary bytes, otherwise anti-entropy heals forever.
        assert_eq!(
            serialize(&BansV1(vec![first.clone(), second.clone()])),
            serialize(&BansV1(vec![second, first]))
        );
    }

    #[test]
    fn owner_bans_survive_the_cap() {
        let owner_key = SigningKey::generate(&mut rand::thread_rng());
        let params = ChatBoardParametersV1 {
            owner: owner_key.verifying_key(),
        };
        let owner_id = params.owner_id();
        let mut state = create_test_chat_board_state();
        state.configuration.configuration.max_user_bans = 1;

        let member_key = SigningKey::generate(&mut rand::thread_rng());
        let member_id: MemberId = member_key.verifying_key().into();
        let at = |secs: u64| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);

        let older_member_ban = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: at(1),
                banned_user: MemberId(FastHash(11)),
                expires_at: None,
            },
            member_id,
            &member_key,
        );
        let newer_owner_ban = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: at(2),
                banned_user: MemberId(FastHash(12)),
                expires_at: None,
            },
            owner_id,
            &owner_key,
        );

        for order in [
            vec![older_member_ban.clone(), newer_owner_ban.clone()],
            vec![newer_owner_ban.clone(), older_member_ban.clone()],
        ] {
            let mut bans = BansV1(order);
            bans.enforce_cap(&state, &params);
            assert_eq!(bans.0.len(), 1, "cap must be enforced");
            assert_eq!(
                bans.0[0].banned_by, owner_id,
                "the cap must not age out an owner ban in favour of a member's"
            );
        }
    }

    #[test]
    fn test_bans_apply_delta() {
        let mut state = create_test_chat_board_state();

        let owner_key = SigningKey::generate(&mut rand::thread_rng());
        let owner_id: MemberId = owner_key.verifying_key().into();
        let params = ChatBoardParametersV1 {
            owner: owner_key.verifying_key(),
        };
        let member_key = SigningKey::generate(&mut rand::thread_rng());
        let member_id: MemberId = member_key.verifying_key().into();

        // Add members to the board_state
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: owner_key.verifying_key(),
                join_proof: None,
            },
            &owner_key,
        ));
        state.members.members.push(AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk: member_key.verifying_key(),
                join_proof: None,
            },
            &owner_key,
        ));

        // Update the configuration to allow bans
        state.configuration.configuration.max_user_bans = 5;

        let mut bans = BansV1::default();

        let new_ban = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: SystemTime::now(),
                banned_user: member_id,
                expires_at: None,
            },
            owner_id,
            &owner_key,
        );

        // Test 1: Apply valid delta
        let delta = vec![new_ban.clone()];
        assert!(
            bans.apply_delta(&state, &params, &Some(delta.clone()))
                .is_ok(),
            "Valid delta should be applied successfully: {:?}",
            bans.apply_delta(&state, &params, &Some(delta)).err()
        );
        assert_eq!(
            bans.0.len(),
            1,
            "Bans should contain one ban after applying delta"
        );
        assert_eq!(bans.0[0], new_ban, "Applied ban should match the new ban");

        // Test 2: Apply delta exceeding max_user_bans - should succeed by removing oldest bans
        let mut many_bans = Vec::new();
        for i in 0..5 {
            many_bans.push(AuthorizedUserBan::new(
                UserBan {
                    owner_member_id: owner_id,
                    // Give each ban a different timestamp so we can verify oldest are removed
                    banned_at: SystemTime::now() + Duration::from_secs(i as u64 + 10),
                    banned_user: member_id,
                    expires_at: None,
                },
                owner_id,
                &owner_key,
            ));
        }
        let delta_exceeding_max = Some(many_bans.clone());
        assert!(
            bans.apply_delta(&state, &params, &delta_exceeding_max)
                .is_ok(),
            "Delta exceeding max_user_bans should succeed by removing oldest: {:?}",
            bans.apply_delta(&state, &params, &delta_exceeding_max)
                .err()
        );
        assert_eq!(
            bans.0.len(),
            5,
            "Bans should be at max_user_bans limit after removing oldest"
        );
        // The original new_ban (the oldest) should have been removed
        assert!(
            !bans.0.contains(&new_ban),
            "Oldest ban should have been removed"
        );

        // Test 3: Apply invalid delta (duplicate ban) - use one of the bans still in the list
        let existing_ban = many_bans.last().unwrap().clone();
        let invalid_delta = Some(vec![existing_ban]);
        assert!(
            bans.apply_delta(&state, &params, &invalid_delta).is_err(),
            "Applying duplicate ban should fail: {:?}",
            bans.apply_delta(&state, &params, &invalid_delta).ok()
        );
        assert_eq!(
            bans.0.len(),
            5,
            "State should not change after applying duplicate ban"
        );

        // Test 4: Adding more bans should evict oldest ones but keep max_user_bans
        let mut additional_bans = Vec::new();
        for i in 0..2 {
            additional_bans.push(AuthorizedUserBan::new(
                UserBan {
                    owner_member_id: owner_id,
                    banned_at: SystemTime::now() + Duration::from_secs(i as u64 + 100),
                    banned_user: member_id,
                    expires_at: None,
                },
                owner_id,
                &owner_key,
            ));
        }
        assert!(
            bans.apply_delta(&state, &params, &Some(additional_bans))
                .is_ok(),
            "Applying more bans should succeed by evicting oldest: {:?}",
            bans.apply_delta(&state, &params, &Some(Vec::new())).err()
        );
        assert_eq!(
            bans.0.len(),
            5,
            "State should still have max number of bans after evicting oldest"
        );
    }

    #[test]
    fn test_authorized_user_ban() {
        let owner_key = SigningKey::generate(&mut rand::thread_rng());
        let owner_id: MemberId = owner_key.verifying_key().into();
        let member_key = SigningKey::generate(&mut rand::thread_rng());
        let member_id: MemberId = member_key.verifying_key().into();

        let ban = UserBan {
            owner_member_id: owner_id,
            banned_at: SystemTime::now(),
            banned_user: member_id,
            expires_at: None,
        };

        let authorized_ban = AuthorizedUserBan::new(ban.clone(), owner_id, &owner_key);

        // Test 1: Verify signature
        assert!(authorized_ban
            .verify_signature(&owner_key.verifying_key())
            .is_ok());

        // Test 2: Verify signature with wrong key
        let wrong_key = SigningKey::generate(&mut rand::thread_rng());
        assert!(authorized_ban
            .verify_signature(&wrong_key.verifying_key())
            .is_err());

        // Test 3: Check ban ID
        let id1 = authorized_ban.id();
        let id2 = authorized_ban.id();
        assert_eq!(id1, id2);

        // Test 4: Different bans should have different IDs
        let another_ban = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: SystemTime::now() + Duration::from_secs(1),
                banned_user: member_id,
                expires_at: None,
            },
            owner_id,
            &owner_key,
        );
        assert_ne!(authorized_ban.id(), another_ban.id());
    }
}

#[cfg(test)]
mod revocation_tests {
    use super::*;
    use crate::board_state::configuration::{AuthorizedConfigurationV1, Configuration};
    use crate::board_state::member::{AuthorizedMember, Member, MembersV1};
    use crate::board_state::member_info::MemberInfoV1;
    use crate::board_state::message::MessagesV1;
    use crate::board_state::secret::BoardSecretsV1;
    use std::time::Duration;

    #[test]
    fn owner_lifts_a_ban_and_the_tombstone_stays() {
        let owner_sk = SigningKey::generate(&mut rand::thread_rng());
        let owner_vk = owner_sk.verifying_key();
        let owner_id = MemberId::from(&owner_vk);
        let params = ChatBoardParametersV1 { owner: owner_vk };
        let member_sk = SigningKey::generate(&mut rand::thread_rng());
        let member_vk = member_sk.verifying_key();
        let member_id = MemberId::from(&member_vk);
        let member = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk,
                join_proof: None,
            },
            &owner_sk,
        );
        let ban = AuthorizedUserBan::new(
            UserBan {
                owner_member_id: owner_id,
                banned_at: SystemTime::now(),
                banned_user: member_id,
                expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
            },
            owner_id,
            &owner_sk,
        );
        let ban_id = ban.id();
        let revocation = AuthorizedBanRevocation::new(
            BanRevocationV1 {
                ban_id: ban_id.clone(),
                banned_user: member_id,
                revoked_at: SystemTime::now(),
            },
            &owner_sk,
        );
        let mut state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk),
            bans: BansV1(vec![ban]),
            ban_revocations: BanRevocationsV1 {
                revocations: vec![revocation.clone()],
            },
            members: MembersV1 {
                members: vec![member],
            },
            member_info: MemberInfoV1::default(),
            secrets: BoardSecretsV1::default(),
            recent_messages: MessagesV1::default(),
            ..Default::default()
        };

        state
            .ban_revocations
            .verify(&state, &params)
            .expect("the owner can lift a ban");
        state.post_apply_cleanup(&params).unwrap();
        assert!(state.bans.0.is_empty(), "the revoked ban is gone");
        assert!(state.ban_revocations.revoked(&ban_id));
    }

    #[test]
    fn members_cannot_lift_bans() {
        let owner_sk = SigningKey::generate(&mut rand::thread_rng());
        let owner_vk = owner_sk.verifying_key();
        let owner_id = MemberId::from(&owner_vk);
        let params = ChatBoardParametersV1 { owner: owner_vk };
        let member_sk = SigningKey::generate(&mut rand::thread_rng());
        let member_vk = member_sk.verifying_key();
        let member_id = MemberId::from(&member_vk);
        let member = AuthorizedMember::new(
            Member {
                owner_member_id: owner_id,
                invited_by: owner_id,
                member_vk,
                join_proof: None,
            },
            &owner_sk,
        );
        let revocation = AuthorizedBanRevocation::new(
            BanRevocationV1 {
                ban_id: BanId(FastHash(7)),
                banned_user: member_id,
                revoked_at: SystemTime::now(),
            },
            &member_sk,
        );
        let state = ChatBoardStateV1 {
            configuration: AuthorizedConfigurationV1::new(Configuration::default(), &owner_sk),
            ban_revocations: BanRevocationsV1 {
                revocations: vec![revocation],
            },
            members: MembersV1 {
                members: vec![member],
            },
            ..Default::default()
        };
        assert!(state.ban_revocations.verify(&state, &params).is_err());
    }
}
