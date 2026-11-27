//! Notification mode filtering and helpers for per-board notifications.

use crate::board_data::{BoardData, NotificationMode};
use plaza_core::board_state::member::MemberId;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NoticeKind {
    Reply,
    Mention,
    Section,
}

/// Whether a per-board mode lets this notice reach the OS notification layer.
pub fn mode_allows(mode: NotificationMode, kind: NoticeKind) -> bool {
    match mode {
        NotificationMode::All => true,
        NotificationMode::MentionsAndReplies => kind != NoticeKind::Section,
        NotificationMode::Muted => false,
    }
}

/// The nickname other members see, unsealed when the board is private.
pub fn self_nickname(board: &BoardData, self_id: MemberId) -> String {
    board.display_nickname(self_id).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_notification_modes_keep_sections_out_of_mentions_only() {
        assert!(mode_allows(NotificationMode::All, NoticeKind::Section));
        assert!(!mode_allows(
            NotificationMode::MentionsAndReplies,
            NoticeKind::Section
        ));
        assert!(mode_allows(
            NotificationMode::MentionsAndReplies,
            NoticeKind::Mention
        ));
        assert!(!mode_allows(NotificationMode::Muted, NoticeKind::Reply));
    }
}
