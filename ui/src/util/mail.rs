//! Freenet Mail bridge: address validation and the stable app URL.
//!
//! FreeTalk Plaza does not share keys with Freenet Mail. This module only
//! checks the address a user pastes and builds the link to the separate app.

use serde::{Deserialize, Serialize};

/// Stable container contract of Freenet Mail. It survives Mail releases.
pub const MAIL_CONTAINER_ID: &str = "122f6AR7PyF8d8mhczuNQM4xrLtBf5t8g2iB7PEVT7KC";

const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// How much of the address this board may show to other members.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailVisibility {
    /// Keep the address only in this browser.
    #[default]
    Hidden,
    /// Publish it in the board state. Sealed on private boards, public on
    /// public boards.
    Board,
    /// Publish it in clear where the board allows it.
    Public,
}

impl MailVisibility {
    pub fn label(self) -> &'static str {
        match self {
            Self::Hidden => "Hidden",
            Self::Board => "Board members",
            Self::Public => "Public",
        }
    }
}

fn is_base58(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| BASE58.contains(&byte))
}

/// Accept the two forms Freenet Mail produces:
///
/// * `label@address`, where the address is the 35–36 character v2 form or the
///   43–44 character legacy inbox contract id;
/// * the bare address, same lengths.
///
/// The label is cosmetic. The address itself is validated for length and the
/// base58 alphabet; checking that the contract exists happens in Mail.
pub fn normalize_address(input: &str) -> Result<String, &'static str> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Enter a Freenet Mail address.");
    }
    if trimmed
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err("The address cannot contain spaces.");
    }
    let (label, address) = match trimmed.rfind('@') {
        Some(index) => {
            let label = &trimmed[..index];
            let address = &trimmed[index + 1..];
            if label.trim().is_empty() {
                return Err("Add a name before the @, or paste the address alone.");
            }
            if label.chars().count() > 64 {
                return Err("The name before the @ is too long.");
            }
            (Some(label), address)
        }
        None => (None, trimmed),
    };
    if !is_base58(address) {
        return Err("The address uses only base58 letters and digits.");
    }
    let length = address.chars().count();
    if !(35..=36).contains(&length) && !(43..=44).contains(&length) {
        return Err("A Freenet Mail address has 36 characters (or 44 for an older inbox id).");
    }
    Ok(match label {
        Some(label) => format!("{label}@{address}"),
        None => address.to_string(),
    })
}

/// The bookmarkable Freenet Mail URL on the node that serves this page.
pub fn app_url() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(window) = web_sys::window() {
            let scheme = window
                .location()
                .protocol()
                .unwrap_or_else(|_| "http:".to_string());
            let host = window
                .location()
                .host()
                .unwrap_or_else(|_| "127.0.0.1:7509".to_string());
            return format!("{scheme}//{host}/v1/contract/web/{MAIL_CONTAINER_ID}/");
        }
    }
    format!("http://127.0.0.1:7509/v1/contract/web/{MAIL_CONTAINER_ID}/")
}

#[cfg(test)]
mod tests {
    use super::*;

    const V2: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZab";

    #[test]
    fn accepts_named_and_bare_v2_addresses() {
        assert_eq!(
            normalize_address("alice@123456789ABCDEFGHJKLMNPQRSTUVWXYZab").unwrap(),
            format!("alice@{V2}")
        );
        assert_eq!(normalize_address(V2).unwrap(), V2);
    }

    #[test]
    fn accepts_a_legacy_inbox_id() {
        let legacy = "GeQLXXR8sfGe31BNRJoVxkvGUTnBkufJ4gTaoX5NWnU5";
        assert_eq!(normalize_address(legacy).unwrap(), legacy);
    }

    #[test]
    fn rejects_spaces_bad_base58_and_wrong_lengths() {
        assert!(normalize_address("").is_err());
        assert!(normalize_address("alice @3x4g3um9JYXLchv5VE3SD8wW9TnR8oSMLAA7AYfodBFc").is_err());
        assert!(normalize_address("alice@0OIl").is_err());
        assert!(normalize_address("alice@abc").is_err());
        assert!(normalize_address("@3x4g3um9JYXLchv5VE3SD8wW9TnR8oSMLAA7AYfodBFc").is_err());
    }

    #[test]
    fn the_app_url_names_the_stable_container() {
        assert!(app_url().contains(MAIL_CONTAINER_ID));
    }
}
