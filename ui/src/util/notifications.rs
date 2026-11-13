//! Local notification list: replies to my posts, mentions of my nickname and
//! new topics in followed sections, all since the last "mark all read".

use crate::board_data::BoardData;
use crate::components::conversation::{get_all_messages, MessageData};
use crate::util::ecies::unseal_bytes_with_secrets;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NoticeKind {
    Reply,
    Mention,
    Section,
}

pub struct Notice<'a> {
    pub message: &'a MessageData,
    pub kind: NoticeKind,
}

/// The nickname other members see, unsealed when the board is private.
pub fn self_nickname(board: &BoardData, self_id: MemberId) -> String {
    board
        .board_state
        .member_info
        .member_info
        .iter()
        .find(|info| info.member_info.member_id == self_id)
        .map(|info| {
            match unseal_bytes_with_secrets(&info.member_info.preferred_nickname, &board.secrets) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                Err(_) => info.member_info.preferred_nickname.to_string_lossy(),
            }
        })
        .unwrap_or_default()
}

/// Every unread notice, newest first.
///
/// Replies and mentions are new since `last_visit`. New topics in followed
/// sections are new since that section was last opened, so reading a section
/// clears its own notices without hiding the personal ones.
pub fn collect<'a>(
    messages: &'a [MessageData],
    self_id: MemberId,
    nickname: &str,
    last_visit: i64,
    subscriptions: &[MessageId],
    read_categories: &HashMap<MessageId, i64>,
) -> Vec<Notice<'a>> {
    let by_id: HashMap<MessageId, &MessageData> = messages
        .iter()
        .map(|message| (message.message_id, message))
        .collect();
    let followed: HashSet<MessageId> = subscriptions.iter().copied().collect();
    let mention = if nickname.is_empty() {
        String::new()
    } else {
        format!("@{}", nickname.to_lowercase())
    };

    let mut notices = Vec::new();
    for message in messages {
        if message.is_category || message.author_id == self_id {
            continue;
        }
        let time = message.time.timestamp_millis();

        let replied_to_me = message
            .reply_to_message_id
            .and_then(|target| by_id.get(&target))
            .map(|parent| parent.author_id == self_id)
            .unwrap_or(false);
        let mentioned =
            !mention.is_empty() && message.content_text.to_lowercase().contains(&mention);
        let followed_section = if followed.is_empty() {
            None
        } else {
            section_of(message, &by_id)
                .and_then(|section| followed_section(section, &by_id, &followed))
        };

        let kind = if replied_to_me && time > last_visit {
            NoticeKind::Reply
        } else if mentioned && time > last_visit {
            NoticeKind::Mention
        } else if let Some(section) = followed_section {
            let read_upto = read_categories.get(&section).copied().unwrap_or(last_visit);
            if time > read_upto {
                NoticeKind::Section
            } else {
                continue;
            }
        } else {
            continue;
        };
        notices.push(Notice { message, kind });
    }

    notices.sort_by_key(|notice| std::cmp::Reverse(notice.message.time));
    notices
}

/// Number of unread notices for the current board, for the bell badge.
pub fn unread_count(board: &BoardData) -> usize {
    let self_id = MemberId::from(&board.self_sk.verifying_key());
    let nickname = self_nickname(board, self_id);
    let messages = get_all_messages(
        &board.board_state,
        self_id,
        &board.secrets,
        &board.category_secrets,
        &board.old_category_secrets,
    );
    collect(
        &messages,
        self_id,
        &nickname,
        board.last_visit,
        &board.subscribed_categories,
        &board.read_categories,
    )
    .len()
}

/// The section a new topic belongs to: its parent is a category.
fn section_of(
    message: &MessageData,
    by_id: &HashMap<MessageId, &MessageData>,
) -> Option<MessageId> {
    let parent = by_id.get(&message.reply_to_message_id?)?;
    parent.is_category.then_some(parent.message_id)
}

/// The followed section that covers this one, possibly a parent section.
fn followed_section(
    mut section: MessageId,
    by_id: &HashMap<MessageId, &MessageData>,
    followed: &HashSet<MessageId>,
) -> Option<MessageId> {
    for _ in 0..64 {
        if followed.contains(&section) {
            return Some(section);
        }
        section = by_id.get(&section)?.parent_category_id?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use freenet_scaffold::util::FastHash;
    use std::collections::HashMap;

    fn member(seed: u8) -> MemberId {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        MemberId::from(&key.verifying_key())
    }

    #[allow(clippy::too_many_arguments)]
    fn message(
        id: i64,
        author: MemberId,
        time_ms: i64,
        reply_to: Option<MessageId>,
        text: &str,
        is_category: bool,
        parent: Option<MessageId>,
    ) -> MessageData {
        MessageData {
            message_id: MessageId(FastHash(id)),
            author_id: author,
            author_name: format!("member-{id}"),
            is_self: false,
            title_text: format!("post {id}"),
            content_text: text.to_string(),
            content_html: text.to_string(),
            time: chrono::Utc.timestamp_millis_opt(time_ms).unwrap(),
            time_clamped: false,
            edited: false,
            reactions: HashMap::new(),
            reply_to_message_id: reply_to,
            reply_to_author: None,
            reply_to_preview: None,
            receive_delay_secs: None,
            is_category,
            category_name: is_category.then(|| format!("section {id}")),
            category_description: None,
            category_icon: None,
            category_color: None,
            parent_category_id: parent,
            category_allowed_roles: Vec::new(),
            category_hidden: false,
            category_locked: false,
            is_group: false,
            is_pinned: false,
            is_closed: false,
            is_pending: false,
            is_announced: false,
            poll: None,
            merged_into: None,
        }
    }

    #[test]
    fn collect_finds_replies_mentions_and_followed_topics() {
        let me = member(1);
        let other = member(2);
        let section = MessageId(FastHash(100));

        let messages = vec![
            message(100, other, 500, None, "", true, None),
            // New topic in the followed section.
            message(101, other, 2_000, Some(section), "hello", false, None),
            // A reply inside that topic: not a section notice.
            message(
                102,
                other,
                3_000,
                Some(MessageId(FastHash(101))),
                "reply",
                false,
                None,
            ),
            // Mention.
            message(103, other, 4_000, None, "@alice look", false, None),
            // My own post and a reply to it.
            message(104, me, 4_500, None, "mine", false, None),
            message(
                105,
                other,
                5_000,
                Some(MessageId(FastHash(104))),
                "answer",
                false,
                None,
            ),
        ];

        let notices = collect(&messages, me, "Alice", 1_000, &[section], &HashMap::new());
        let ids: Vec<i64> = notices
            .iter()
            .map(|notice| notice.message.message_id.0 .0)
            .collect();
        assert_eq!(ids, vec![105, 103, 101]);
        assert_eq!(notices[0].kind, NoticeKind::Reply);
        assert_eq!(notices[1].kind, NoticeKind::Mention);
        assert_eq!(notices[2].kind, NoticeKind::Section);
    }

    #[test]
    fn following_a_parent_section_covers_subsections() {
        let me = member(1);
        let other = member(2);
        let parent = MessageId(FastHash(100));
        let child = MessageId(FastHash(110));

        let messages = vec![
            message(100, other, 500, None, "", true, None),
            message(110, other, 600, Some(parent), "", true, Some(parent)),
            message(111, other, 2_000, Some(child), "child topic", false, None),
            // Old topic before the last visit.
            message(112, other, 300, Some(parent), "old", false, None),
        ];

        let notices = collect(&messages, me, "Alice", 1_000, &[parent], &HashMap::new());
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].message.message_id.0 .0, 111);
    }

    #[test]
    fn reading_a_followed_section_clears_its_notices() {
        let me = member(1);
        let other = member(2);
        let section = MessageId(FastHash(100));
        let messages = vec![
            message(100, other, 500, None, "", true, None),
            message(101, other, 2_000, Some(section), "hello", false, None),
        ];

        let mut read_categories = HashMap::new();
        read_categories.insert(section, 3_000);
        let notices = collect(&messages, me, "Alice", 1_000, &[section], &read_categories);
        assert!(notices.is_empty());

        // A personal reply is still a notice even after reading the section.
        let messages = vec![
            message(100, other, 500, None, "", true, None),
            message(103, other, 4_000, None, "@alice hi", false, None),
        ];
        let notices = collect(&messages, me, "Alice", 1_000, &[section], &read_categories);
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].kind, NoticeKind::Mention);
    }

    #[test]
    fn without_followed_sections_only_personal_notices_remain() {
        let me = member(1);
        let other = member(2);
        let section = MessageId(FastHash(100));
        let messages = vec![
            message(100, other, 500, None, "", true, None),
            message(101, other, 2_000, Some(section), "hello", false, None),
            message(102, other, 2_000, None, "@alice hi", false, None),
        ];

        let notices = collect(&messages, me, "Alice", 1_000, &[], &HashMap::new());
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].kind, NoticeKind::Mention);
    }
}
