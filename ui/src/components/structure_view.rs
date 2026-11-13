//! Move, merge and split topics between sections.

use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::components::conversation::{get_all_messages, MessageData};
use crate::util::message_actions as actions;
use crate::util::message_actions::ActionContext;
use dioxus::prelude::*;
use plaza_core::board_state::message::MessageId;
use std::collections::HashMap;
use wasm_bindgen_futures::spawn_local;

fn section_of<'a>(topic: &MessageData, all: &'a [MessageData]) -> Option<&'a MessageData> {
    let mut target = topic.reply_to_message_id;
    for _ in 0..64 {
        let id = target?;
        let parent = all.iter().find(|message| message.message_id == id)?;
        if parent.is_category {
            return Some(parent);
        }
        target = parent.reply_to_message_id;
    }
    None
}

#[component]
fn TopicStructure(
    topic: MessageData,
    section_id: Option<MessageId>,
    section_name: String,
    section_author: String,
    sections: Vec<(MessageId, String)>,
    siblings: Vec<(MessageId, String)>,
    replies: Vec<MessageData>,
) -> Element {
    let mut move_index = use_signal(|| {
        section_id
            .and_then(|id| sections.iter().position(|(section, _)| *section == id))
            .unwrap_or(0)
    });
    let mut merge_index = use_signal(|| 0usize);
    let mut error = use_signal(|| None::<String>);

    let topic_id = topic.message_id;
    let title = if topic.title_text.trim().is_empty() {
        "Untitled".to_string()
    } else {
        topic.title_text.clone()
    };
    let reply_ids: Vec<MessageId> = replies.iter().map(|reply| reply.message_id).collect();

    rsx! {
        div { class: "bg-panel border border-border rounded-lg p-3 space-y-2",
            div { class: "flex flex-wrap items-baseline gap-2",
                span { class: "text-text font-medium", "{title}" }
                span { class: "text-xs text-text-muted", "by {topic.author_name}" }
                span { class: "text-xs text-accent", "{section_name}" }
                if topic.is_closed {
                    span { class: "text-xs text-text-muted", "closed" }
                }
            }
            if let Some(message) = error.read().as_ref() {
                p { class: "text-xs text-red-400", "{message}" }
            }
            div { class: "flex flex-wrap items-center gap-2 text-xs",
                span { class: "text-text-muted", "Move to" }
                select {
                    class: "px-2 py-1 bg-surface border border-border rounded text-text",
                    value: "{*move_index.read()}",
                    onchange: move |evt| {
                        if let Ok(index) = evt.value().parse::<usize>() {
                            move_index.set(index);
                        }
                    },
                    for (index, (_, name)) in sections.iter().enumerate() {
                        option { value: "{index}", "{name}" }
                    }
                }
                button {
                    r#type: "button",
                    class: "px-2 py-1 bg-surface hover:bg-surface-hover text-text rounded",
                    onclick: move |_| {
                        let Some((target, _)) = sections.get(*move_index.read()) else {
                            return;
                        };
                        let target = *target;
                        if let Some(ctx) = ActionContext::from_current_board() {
                            match actions::move_post(&ctx, topic_id, Some(target)) {
                                Ok(()) => error.set(None),
                                Err(e) => error.set(Some(e)),
                            }
                        }
                    },
                    "Move"
                }
                if !siblings.is_empty() {
                    span { class: "text-text-muted ml-3", "Merge into" }
                    select {
                        class: "px-2 py-1 bg-surface border border-border rounded text-text",
                        value: "{*merge_index.read()}",
                        onchange: move |evt| {
                            if let Ok(index) = evt.value().parse::<usize>() {
                                merge_index.set(index);
                            }
                        },
                        for (index, (_, name)) in siblings.iter().enumerate() {
                            option { value: "{index}", "{name}" }
                        }
                    }
                    button {
                        r#type: "button",
                        class: "px-2 py-1 bg-surface hover:bg-surface-hover text-text rounded",
                        onclick: {
                            let reply_ids = reply_ids.clone();
                            move |_| {
                                let Some((destination, _)) = siblings.get(*merge_index.read()) else {
                                    return;
                                };
                                let destination = *destination;
                                if let Some(ctx) = ActionContext::from_current_board() {
                                    match actions::merge_topic(
                                        &ctx,
                                        topic_id,
                                        destination,
                                        reply_ids.clone(),
                                    ) {
                                        Ok(()) => error.set(None),
                                        Err(e) => error.set(Some(e)),
                                    }
                                }
                            }
                        },
                        "Merge"
                    }
                }
            }
            if !replies.is_empty() {
                details { class: "text-xs text-text-muted",
                    summary { class: "cursor-pointer select-none",
                        "Replies ({replies.len()})"
                    }
                    if let Some(section_id) = section_id {
                        div { class: "mt-2 space-y-1",
                            for reply in replies.iter() {
                                ReplySplitRow {
                                    key: "{reply.message_id.0 .0}",
                                    reply: reply.clone(),
                                    section_id: section_id,
                                    section_name: section_name.clone(),
                                    section_author: section_author.clone(),
                                }
                            }
                        }
                    } else {
                        p { class: "mt-2", "Split needs a topic inside a section." }
                    }
                }
            }
        }
    }
}

#[component]
fn ReplySplitRow(
    reply: MessageData,
    section_id: MessageId,
    section_name: String,
    section_author: String,
) -> Element {
    let mut title = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let reply_id = reply.message_id;
    let reply_label = if reply.title_text.trim().is_empty() {
        reply.content_text.chars().take(48).collect::<String>()
    } else {
        reply.title_text.clone()
    };
    let placeholder = format!("Split {reply_label}");
    rsx! {
        div { class: "flex flex-wrap items-center gap-2",
            span { class: "text-text truncate max-w-64",
                "{reply.author_name}: {reply_label}"
            }
            input {
                class: "flex-1 min-w-40 px-2 py-1 bg-surface border border-border rounded text-text",
                placeholder: "{placeholder}",
                value: "{title}",
                oninput: move |evt| title.set(evt.value()),
            }
            button {
                r#type: "button",
                class: "px-2 py-1 bg-surface hover:bg-surface-hover text-text rounded",
                onclick: move |_| {
                    let Some(ctx) = ActionContext::from_current_board() else {
                        return;
                    };
                    let chosen = title.read().trim().to_string();
                    let chosen = if chosen.is_empty() {
                        placeholder.clone()
                    } else {
                        chosen
                    };
                    let section_author = section_author.clone();
                    let section_name = section_name.clone();
                    spawn_local(async move {
                        if let Err(e) = actions::split_reply(
                            &ctx,
                            reply_id,
                            section_id,
                            section_author,
                            format!("[Section] {section_name}"),
                            chosen,
                        )
                        .await
                        {
                            error.set(Some(e));
                        }
                    });
                },
                "Split"
            }
            if let Some(message) = error.read().as_ref() {
                span { class: "text-red-400", "{message}" }
            }
        }
    }
}

#[component]
pub fn StructureView() -> Element {
    let board = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .and_then(|key| BOARDS.read().map.get(&key).cloned())
    });
    let Some(board) = board.read().clone() else {
        return rsx! {};
    };
    let self_id = plaza_core::board_state::member::MemberId::from(&board.self_sk.verifying_key());
    let messages = get_all_messages(
        &board.board_state,
        self_id,
        &board.secrets,
        &board.category_secrets,
        &board.old_category_secrets,
    );

    let sections: Vec<(MessageId, String)> = messages
        .iter()
        .filter(|message| message.is_category && !message.is_group && !message.category_locked)
        .map(|message| {
            (
                message.message_id,
                message
                    .category_name
                    .clone()
                    .unwrap_or_else(|| "Section".to_string()),
            )
        })
        .collect();
    let section_names: HashMap<MessageId, String> = sections.iter().cloned().collect();

    let topics: Vec<MessageData> = messages
        .iter()
        .filter(|message| {
            if message.is_category || message.merged_into.is_some() {
                return false;
            }
            if message.is_top_level_post() {
                return true;
            }
            // A topic inside a section replies to the section category.
            message
                .reply_to_message_id
                .and_then(|id| messages.iter().find(|parent| parent.message_id == id))
                .map(|parent| parent.is_category && !parent.is_group)
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let topic_titles: HashMap<MessageId, String> = topics
        .iter()
        .map(|topic| {
            (
                topic.message_id,
                if topic.title_text.trim().is_empty() {
                    "Untitled".to_string()
                } else {
                    topic.title_text.clone()
                },
            )
        })
        .collect();

    rsx! {
        div { class: "flex flex-col gap-3",
            p { class: "text-text-muted text-sm",
                "Move a topic to another section, merge it into another topic, or split one reply into its own topic."
            }
            if topics.is_empty() {
                p { class: "text-text-muted text-sm", "No topics yet." }
            }
            for topic in topics.iter() {
                {
                    let section = section_of(topic, &messages);
                    let section_id = section.map(|s| s.message_id);
                    let section_name = section_id
                        .and_then(|id| section_names.get(&id).cloned())
                        .unwrap_or_else(|| "Ungrouped".to_string());
                    let section_author = section
                        .map(|s| s.author_name.clone())
                        .unwrap_or_default();
                    let siblings: Vec<(MessageId, String)> = topics
                        .iter()
                        .filter(|other| {
                            other.message_id != topic.message_id
                                && section_of(other, &messages).map(|s| s.message_id) == section_id
                        })
                        .filter_map(|other| {
                            topic_titles
                                .get(&other.message_id)
                                .map(|title| (other.message_id, title.clone()))
                        })
                        .collect();
                    let replies: Vec<MessageData> = messages
                        .iter()
                        .filter(|message| {
                            !message.is_category
                                && message.reply_to_message_id == Some(topic.message_id)
                        })
                        .cloned()
                        .collect();
                    rsx! {
                        TopicStructure {
                            key: "{topic.message_id.0 .0}",
                            topic: topic.clone(),
                            section_id: section_id,
                            section_name: section_name,
                            section_author: section_author,
                            sections: sections.clone(),
                            siblings: siblings,
                            replies: replies,
                        }
                    }
                }
            }
        }
    }
}
