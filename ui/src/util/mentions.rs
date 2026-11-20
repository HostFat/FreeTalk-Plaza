//! @mention parsing, chips and composer autocomplete helpers.
//!
//! Messages carry plain `@Nickname` text. The composer inserts an explicit
//! `@[Nickname](mention:<member-id>)` token so a chip stays attached to the
//! member even after a rename. Both forms are rendered as one chip.

use crate::board_data::BoardData;
use plaza_core::board_state::member::MemberId;
use std::collections::HashSet;
use std::str::FromStr;

const OPEN: char = '\u{E000}';
const CLOSE: char = '\u{E001}';
const MAX_QUERY: u32 = 48;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MentionDirectory {
    members: Vec<MentionMember>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MentionMember {
    pub id: MemberId,
    pub name: String,
    lower: String,
}

impl MentionDirectory {
    pub fn from_names(names: impl IntoIterator<Item = (MemberId, String)>) -> Self {
        let mut seen = HashSet::new();
        let mut members: Vec<MentionMember> = names
            .into_iter()
            .filter(|(_, name)| {
                let name = name.trim();
                !name.is_empty() && name != "Unknown"
            })
            .filter(|(id, _)| seen.insert(*id))
            .map(|(id, name)| MentionMember {
                id,
                lower: name.to_lowercase(),
                name,
            })
            .collect();
        members.sort_by(|a, b| {
            b.name
                .chars()
                .count()
                .cmp(&a.name.chars().count())
                .then_with(|| a.name.cmp(&b.name))
        });
        Self { members }
    }

    /// Every member with a usable nickname, including the owner when the owner
    /// has no member record.
    pub fn from_board(board: &BoardData) -> Self {
        let mut names: Vec<(MemberId, String)> = board
            .board_state
            .member_info
            .member_info
            .iter()
            .map(|info| {
                let id = info.member_info.member_id;
                (
                    id,
                    board
                        .display_nickname(id)
                        .unwrap_or_else(|| id.to_string()),
                )
            })
            .collect();
        for member in &board.board_state.members.members {
            let id = member.member.id();
            names.push((
                id,
                board
                    .display_nickname(id)
                    .unwrap_or_else(|| id.to_string()),
            ));
        }
        let owner = MemberId::from(&board.owner_vk);
        names.push((
            owner,
            board
                .display_nickname(owner)
                .unwrap_or_else(|| "Unknown".to_string()),
        ));
        Self::from_names(names)
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Members matching the text after `@`, best matches first.
    pub fn search(&self, query: &str) -> Vec<MentionMember> {
        let query = query.trim().to_lowercase();
        let mut matches: Vec<MentionMember> = self
            .members
            .iter()
            .filter(|member| query.is_empty() || member.lower.contains(&query))
            .cloned()
            .collect();
        matches.sort_by(|a, b| {
            b.lower
                .starts_with(&query)
                .cmp(&a.lower.starts_with(&query))
                .then_with(|| a.name.cmp(&b.name))
        });
        matches.truncate(8);
        matches
    }

    /// Markdown plus mention chips. Plain `@Nickname` and explicit tokens both
    /// become a `plaza-mention` span with a data-member-id.
    pub fn render_html(&self, text: &str, self_id: Option<MemberId>) -> String {
        let (masked, chips) = self.mask_mentions(text);
        let html = crate::util::markdown::text_to_html(&masked);
        restore_chips(&html, &chips, self_id)
    }

    fn mask_mentions(&self, text: &str) -> (String, Vec<(MemberId, String)>) {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::with_capacity(text.len());
        let mut chips: Vec<(MemberId, String)> = Vec::new();
        let mut in_fence = false;
        let mut in_inline = false;
        let mut line_start = true;
        let mut i = 0;
        while i < chars.len() {
            let ch = chars[i];
            // Fenced code blocks never contain mentions.
            if line_start && (ch == '`' || ch == '~') {
                let mut run = 1;
                while i + run < chars.len() && chars[i + run] == ch {
                    run += 1;
                }
                if run >= 3 {
                    in_fence = !in_fence;
                    for _ in 0..run {
                        out.push(ch);
                    }
                    i += run;
                    line_start = false;
                    continue;
                }
            }
            if ch == '\n' {
                out.push(ch);
                i += 1;
                line_start = true;
                continue;
            }
            if !in_fence && ch == '`' {
                in_inline = !in_inline;
                out.push(ch);
                i += 1;
                line_start = false;
                continue;
            }
            if !in_fence && !in_inline && ch == '@' {
                if let Some((end, id, name)) = parse_explicit(&chars, i) {
                    out.push(OPEN);
                    out.push_str(&chips.len().to_string());
                    out.push(CLOSE);
                    chips.push((id, name));
                    i = end;
                    line_start = false;
                    continue;
                }
                let prev_ok = i == 0 || {
                    let prev = chars[i - 1];
                    !prev.is_alphanumeric() && prev != '_' && prev != '@'
                };
                if prev_ok {
                    let rest: String = chars[i + 1..].iter().collect();
                    let rest_lower = rest.to_lowercase();
                    let matched = self.members.iter().find(|member| {
                        if !rest_lower.starts_with(&member.lower) {
                            return false;
                        }
                        match rest.chars().nth(member.name.chars().count()) {
                            Some(after) => !after.is_alphanumeric() && after != '_',
                            None => true,
                        }
                    });
                    if let Some(member) = matched {
                        out.push(OPEN);
                        out.push_str(&chips.len().to_string());
                        out.push(CLOSE);
                        chips.push((member.id, member.name.clone()));
                        i += 1 + member.name.chars().count();
                        line_start = false;
                        continue;
                    }
                }
            }
            out.push(ch);
            i += 1;
            line_start = false;
        }
        (out, chips)
    }
}

/// Parse `@[Name](mention:<id>)` starting at `start` (the `@`).
fn parse_explicit(chars: &[char], start: usize) -> Option<(usize, MemberId, String)> {
    if start + 2 >= chars.len() || chars[start + 1] != '[' {
        return None;
    }
    // Find `]` and the exact `(mention:` opener.
    let mut close = start + 2;
    while close < chars.len() && chars[close] != ']' {
        // A newline or another @ means this is not a token.
        if chars[close] == '\n' || chars[close] == '@' {
            return None;
        }
        close += 1;
    }
    if close + 9 >= chars.len() {
        return None;
    }
    let opener: String = chars[close + 1..close + 10].iter().collect();
    if opener != "(mention:" {
        return None;
    }
    let mut end = close + 10;
    while end < chars.len() && chars[end] != ')' {
        if chars[end] == '\n' || chars[end] == ' ' {
            return None;
        }
        end += 1;
    }
    if end >= chars.len() || chars[end] != ')' {
        return None;
    }
    let id_text: String = chars[close + 10..end].iter().collect();
    let id = MemberId::from_str(&id_text).ok()?;
    let name: String = chars[start + 2..close].iter().collect();
    Some((end + 1, id, name))
}

fn restore_chips(
    html: &str,
    chips: &[(MemberId, String)],
    self_id: Option<MemberId>,
) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(open_at) = rest.find(OPEN) {
        out.push_str(&rest[..open_at]);
        let after = &rest[open_at + OPEN.len_utf8()..];
        let Some(close_at) = after.find(CLOSE) else {
            out.push_str(&rest[open_at..]);
            return out;
        };
        let index = &after[..close_at];
        let consumed = open_at + OPEN.len_utf8() + index.len() + CLOSE.len_utf8();
        match index.parse::<usize>().ok().and_then(|index| chips.get(index)) {
            Some((id, name)) => {
                out.push_str(&chip_html(id, name, self_id == Some(*id)));
            }
            None => out.push_str(&rest[open_at..consumed]),
        }
        rest = &rest[consumed..];
    }
    out.push_str(rest);
    out
}

fn chip_html(id: &MemberId, name: &str, is_self: bool) -> String {
    let class = if is_self {
        "plaza-mention plaza-mention-self"
    } else {
        "plaza-mention"
    };
    format!(
        r#"<span class="{class}" data-member-id="{id}" title="View {}">@{}</span>"#,
        escape_attr(name),
        escape_html(name)
    )
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn escape_attr(text: &str) -> String {
    escape_html(text)
}

/// Token inserted by the composer. Brackets in the name are escaped so the
/// markdown link syntax stays intact.
pub fn mention_token(member: &MentionMember) -> String {
    let name = member
        .name
        .replace('\\', "\\\\")
        .replace('[', "\\[")
        .replace(']', "\\]");
    format!("@[{}](mention:{})", name, member.id)
}

pub fn mention_token_for(id: &MemberId, name: &str) -> String {
    mention_token(&MentionMember {
        id: *id,
        name: name.to_string(),
        lower: name.to_lowercase(),
    })
}

/// Current `@query` at the textarea caret, with UTF-16 range for replacement.
#[cfg(target_arch = "wasm32")]
pub fn textarea_context(id: &str) -> Option<MentionAutocomplete> {
    let start = crate::util::textarea_mention_start(id, MAX_QUERY);
    if start < 0 {
        return None;
    }
    let query = crate::util::textarea_mention_query(id);
    let end = crate::util::textarea_mention_end(id);
    Some(MentionAutocomplete {
        start: start as u32,
        end,
        query,
        selected: 0,
    })
}

/// Replace the active `@query` with a mention token and return the new value.
pub fn replace_context(id: &str, context: &MentionAutocomplete, member: &MentionMember) -> String {
    #[cfg(target_arch = "wasm32")]
    {
        crate::util::textarea_replace_range(
            id,
            context.start,
            context.end,
            &mention_token(member),
        )
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (id, context, member);
        String::new()
    }
}

/// Turn explicit tokens back into readable `@Name` text for the edit form.
pub fn readable_mentions(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '@' {
            if let Some((end, _, name)) = parse_explicit(&chars, index) {
                out.push('@');
                out.push_str(&name);
                index = end;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

/// Whether a message mentions this member, using either a plain `@Nickname`
/// or the explicit `@[Nickname](mention:<id>)` token inserted by autocomplete.
pub fn mentions_member(text: &str, member_id: MemberId, nickname: &str) -> bool {
    if text.contains(&format!("](mention:{member_id})")) {
        return true;
    }
    if nickname.is_empty() {
        return false;
    }
    let needle = format!("@{}", nickname.to_lowercase());
    let lower = text.to_lowercase();
    let mut from = 0;
    while let Some(offset) = lower[from..].find(&needle) {
        let start = from + offset;
        let before_ok = text[..start]
            .chars()
            .next_back()
            .map(|ch| !ch.is_alphanumeric() && ch != '_' && ch != '@')
            .unwrap_or(true);
        let after_ok = text[start + needle.len()..]
            .chars()
            .next()
            .map(|ch| !ch.is_alphanumeric() && ch != '_')
            .unwrap_or(true);
        if before_ok && after_ok {
            return true;
        }
        from = start + needle.len();
    }
    false
}

#[derive(Clone, Debug, PartialEq)]
pub struct MentionAutocomplete {
    pub start: u32,
    pub end: u32,
    pub query: String,
    pub selected: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(n: u8, name: &str) -> (MemberId, String) {
        (MemberId::from_bytes([n; 32]), name.to_string())
    }

    fn directory() -> MentionDirectory {
        MentionDirectory::from_names(vec![
            member(1, "Alice"),
            member(2, "Alice Smith"),
            member(3, "Bob"),
        ])
    }

    #[test]
    fn plain_mentions_become_chips() {
        let html = directory().render_html("hi @Alice and @Bob", Some(MemberId::from_bytes([3; 32])));
        assert!(html.contains("data-member-id="));
        assert!(html.contains("plaza-mention-self"));
        assert!(html.contains(">@Alice</span>"), "{html}");
        assert!(html.contains(">@Bob</span>"), "{html}");
    }

    #[test]
    fn longest_name_wins() {
        let html = directory().render_html("@Alice Smith", None);
        assert!(html.contains(">@Alice Smith</span>"), "{html}");
        assert!(!html.contains(">@Alice</span>"), "{html}");
    }

    #[test]
    fn explicit_token_survives_rename() {
        let id = MemberId::from_bytes([7; 32]);
        let text = format!("@[Old Name](mention:{id})");
        let html = directory().render_html(&text, None);
        assert!(html.contains(">@Old Name</span>"), "{html}");
        assert!(html.contains(&format!(r#"data-member-id="{id}""#)), "{html}");
    }

    #[test]
    fn code_is_not_touched() {
        let html = directory().render_html("`@Alice`\n```\n@Alice\n```", None);
        assert!(!html.contains("data-member-id"), "{html}");
        assert!(html.contains("@Alice"), "{html}");
    }

    #[test]
    fn email_is_not_a_mention() {
        let html = directory().render_html("write to a@Alice.com", None);
        assert!(!html.contains("data-member-id"), "{html}");
    }

    #[test]
    fn search_orders_prefix_matches_first() {
        let found = directory().search("ali");
        assert_eq!(found[0].name, "Alice");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn notification_matching_understands_tokens_and_plain_names() {
        let id = MemberId::from_bytes([4; 32]);
        assert!(mentions_member("hello @Bob", id, "Bob"));
        assert!(mentions_member(
            &format!("hello @[Bob](mention:{id})"),
            id,
            "Bob"
        ));
        assert!(mentions_member("hello @bob", id, "Bob"));
        assert!(!mentions_member("mail me at a@Bob.com", id, "Bob"));
        assert!(!mentions_member("hello @Bobby", id, "Bob"));
    }
}
