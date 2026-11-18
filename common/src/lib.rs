pub mod board_state;
pub mod chat_delegate;
pub mod crypto_values;
pub mod util;

/// Contract revision marker. Bump it when the board contract changes: the
/// wasm (and therefore the contract key) changes, and clients exercise the
/// migration/upgrade-pointer path.
pub const CONTRACT_REVISION: u32 = 2;
pub mod web_container;

pub use board_state::ChatBoardStateV1;
pub use web_container::WebContainerMetadata;
