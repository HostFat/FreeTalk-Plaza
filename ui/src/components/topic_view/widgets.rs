//! Reusable reaction bar and poll widgets rendered inside `TopicView`.

use super::*;

#[component]
pub(super) fn ReactionBar(
    reactions: BTreeMap<String, Vec<MemberId>>,
    member_names: HashMap<MemberId, String>,
    reactions_enabled: bool,
    owner: ed25519_dalek::VerifyingKey,
    topic_id: MessageId,
    part: u32,
    target: MessageId,
    self_id: MemberId,
) -> Element {
    let mut open_owners = use_signal(|| None::<String>);
    let mut open_picker = use_signal(|| false);

    if !reactions_enabled {
        return rsx! {};
    }

    let mut ordered_emojis: Vec<String> = REACTIONS.iter().map(|e| (*e).to_string()).collect();
    for emoji in reactions.keys() {
        if !ordered_emojis.contains(emoji) {
            ordered_emojis.push(emoji.clone());
        }
    }

    rsx! {
        div { class: "relative mt-2 flex items-center gap-1.5 flex-wrap",
            for emoji in ordered_emojis {
                {
                    let members = reactions.get(&emoji).cloned().unwrap_or_default();
                    let count = members.len();
                    let mine = members.contains(&self_id);
                    let value = emoji.clone();
                    let names: Vec<String> = members
                        .iter()
                        .map(|m| {
                            if *m == self_id {
                                "You".to_string()
                            } else {
                                member_names
                                    .get(m)
                                    .cloned()
                                    .unwrap_or_else(|| short_id(*m))
                            }
                        })
                        .collect();
                    let tooltip = if count == 0 {
                        format!("React with {emoji}")
                    } else if mine {
                        format!("{} (click to remove)", names.join(", "))
                    } else {
                        format!("{} (click to add)", names.join(", "))
                    };
                    let class = if mine {
                        "reaction-chip relative inline-flex items-center px-2 py-0.5 rounded-full border border-accent/60 bg-accent/15 text-xs text-accent cursor-pointer"
                    } else {
                        "reaction-chip relative inline-flex items-center px-2 py-0.5 rounded-full border border-border bg-surface text-xs text-text-muted hover:border-accent/50 cursor-pointer"
                    };
                    let emoji_for_owners = emoji.clone();
                    rsx! {
                        button {
                            key: "{emoji}",
                            r#type: "button",
                            class: "{class}",
                            title: "{tooltip}",
                            onclick: move |_| {
                                let value = value.clone();
                                spawn(async move {
                                    let _ = topic_contract::toggle_reaction(
                                        owner,
                                        topic_id,
                                        part,
                                        target,
                                        value,
                                        !mine,
                                    )
                                    .await;
                                });
                            },
                            "{emoji}"
                            if count > 0 {
                                span {
                                    class: "reaction-count ml-1 px-0.5 hover:underline",
                                    title: "Show who reacted",
                                    aria_label: "Show who reacted",
                                    onclick: move |event| {
                                        event.stop_propagation();
                                        open_owners.set(Some(emoji_for_owners.clone()));
                                    },
                                    "{count}"
                                }
                                span { class: "reaction-tooltip", "{tooltip}" }
                            }
                        }
                    }
                }
            }
            div { class: "relative",
                button {
                    r#type: "button",
                    class: "px-2 py-0.5 rounded-full border border-border bg-surface text-xs text-text-muted hover:border-accent/50",
                    title: "Add reaction",
                    onclick: move |event| {
                        event.stop_propagation();
                        let next = !*open_picker.read();
                        open_picker.set(next);
                    },
                    "+"
                }
                if *open_picker.read() {
                    div { class: "absolute left-0 bottom-full mb-1 z-50",
                        EmojiPicker {
                            on_select: {
                                let reactions_for_picker = reactions.clone();
                                move |emoji: String| {
                                    let mine = reactions_for_picker
                                        .get(&emoji)
                                        .is_some_and(|members| members.contains(&self_id));
                                    spawn(async move {
                                        let _ = topic_contract::toggle_reaction(
                                            owner,
                                            topic_id,
                                            part,
                                            target,
                                            emoji,
                                            !mine,
                                        )
                                        .await;
                                    });
                                }
                            },
                            on_close: move |_| open_picker.set(false),
                        }
                    }
                }
            }
        }
        if let Some(emoji) = open_owners() {
            if let Some(reactors) = reactions.get(&emoji) {
                div {
                    class: "fixed inset-0 z-[70] flex items-center justify-center bg-black/40 p-4",
                    onclick: move |_| open_owners.set(None),
                    div {
                        class: "reaction-owners-popover w-full max-w-xs rounded-xl border border-border bg-panel p-4 shadow-xl",
                        onclick: move |event| event.stop_propagation(),
                        div { class: "mb-2 text-lg font-semibold text-text", "{emoji} reactions" }
                        div { class: "space-y-1",
                            for reactor in reactors {
                                div { class: "text-sm text-text",
                                    if *reactor == self_id {
                                        "You"
                                    } else {
                                        {member_names.get(reactor).cloned().unwrap_or_else(|| short_id(*reactor))}
                                    }
                                }
                            }
                        }
                        button {
                            r#type: "button",
                            class: "mt-3 w-full rounded-lg bg-surface px-3 py-1.5 text-sm text-text hover:bg-surface-hover",
                            onclick: move |_| open_owners.set(None),
                            "Close"
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub(super) fn PollBlock(
    poll: PollContentV1,
    counts: Vec<Vec<MemberId>>,
    owner: ed25519_dalek::VerifyingKey,
    topic_id: MessageId,
    part: u32,
    poll_id: MessageId,
    self_id: MemberId,
    can_edit: bool,
    edited: bool,
) -> Element {
    let mut editing = use_signal(|| false);
    let mut edit_question = use_signal(String::new);
    let mut edit_options = use_signal(Vec::<String>::new);
    let mut edit_busy = use_signal(|| false);
    let mut edit_error = use_signal(|| None::<String>);

    let total: usize = counts.iter().map(|members| members.len()).sum();
    let now = plaza_core::board_state::rate_limit::system_time_ms(
        crate::util::get_current_system_time(),
    );
    let closed = poll.closes_at.is_some_and(|closes| closes <= now);
    let my_votes: Vec<u16> = counts
        .iter()
        .enumerate()
        .filter_map(|(idx, members)| members.contains(&self_id).then_some(idx as u16))
        .collect();

    rsx! {
        div { class: "mt-2 rounded-lg border border-border bg-surface p-3",
            if *editing.read() {
                div { class: "flex flex-col gap-2",
                    input {
                        class: "w-full px-3 py-1.5 bg-panel border border-border rounded-lg text-sm text-text",
                        placeholder: "Poll question",
                        value: "{edit_question}",
                        oninput: move |event| edit_question.set(event.value()),
                    }
                    for (index, opt) in edit_options.read().iter().enumerate() {
                        div {
                            key: "edit-poll-opt-{index}",
                            class: "flex items-center gap-2",
                            input {
                                class: "flex-1 px-3 py-1.5 bg-panel border border-border rounded-lg text-sm text-text",
                                placeholder: "Option {index + 1}",
                                value: "{opt}",
                                oninput: move |event| {
                                    let val = event.value();
                                    edit_options.with_mut(|list| {
                                        if let Some(slot) = list.get_mut(index) {
                                            *slot = val;
                                        }
                                    });
                                },
                            }
                            if edit_options.read().len() > 2 {
                                button {
                                    r#type: "button",
                                    class: "px-2 py-1 text-xs text-text-muted hover:text-red-400",
                                    onclick: move |_| {
                                        edit_options.with_mut(|list| {
                                            if list.len() > 2 && index < list.len() {
                                                list.remove(index);
                                            }
                                        });
                                    },
                                    "×"
                                }
                            }
                        }
                    }
                    button {
                        r#type: "button",
                        class: "self-start text-xs text-accent hover:underline",
                        onclick: move |_| {
                            edit_options.with_mut(|list| {
                                if list.len() < 10 {
                                    list.push(String::new());
                                }
                            });
                        },
                        "+ Add option"
                    }
                    if let Some(msg) = edit_error.read().as_ref() {
                        p { class: "text-xs text-red-400", "{msg}" }
                    }
                    div { class: "flex justify-end gap-2",
                        button {
                            r#type: "button",
                            class: "px-3 py-1 rounded-lg border border-border text-xs text-text",
                            onclick: move |_| editing.set(false),
                            "Cancel"
                        }
                        button {
                            r#type: "button",
                            class: "px-3 py-1 rounded-lg bg-accent text-white text-xs disabled:opacity-50",
                            disabled: *edit_busy.read(),
                            onclick: {
                                let base_poll = poll.clone();
                                move |_| {
                                    if *edit_busy.read() {
                                        return;
                                    }
                                    edit_busy.set(true);
                                    edit_error.set(None);
                                    let mut updated = base_poll.clone();
                                    updated.title = edit_question.read().clone();
                                    updated.options = edit_options.read().clone();
                                    spawn(async move {
                                        match topic_contract::edit_poll(
                                            owner,
                                            topic_id,
                                            part,
                                            poll_id,
                                            updated,
                                        )
                                        .await
                                        {
                                            Ok(()) => editing.set(false),
                                            Err(msg) => edit_error.set(Some(msg)),
                                        }
                                        edit_busy.set(false);
                                    });
                                }
                            },
                            if *edit_busy.read() { "Saving…" } else { "Save poll" }
                        }
                    }
                }
            } else {
                div { class: "flex items-start justify-between gap-2",
                    p { class: "text-sm font-medium text-text", "{poll.title}" }
                    if can_edit {
                        button {
                            r#type: "button",
                            class: "text-xs text-accent hover:underline shrink-0",
                            onclick: {
                                let q = poll.title.clone();
                                let opts = poll.options.clone();
                                move |_| {
                                    edit_question.set(q.clone());
                                    edit_options.set(opts.clone());
                                    edit_error.set(None);
                                    editing.set(true);
                                }
                            },
                            "Edit poll"
                        }
                    }
                }
                if !poll.description.trim().is_empty() {
                    p { class: "mt-1 text-xs text-text-muted", "{poll.description}" }
                }
                div { class: "mt-2 flex flex-col gap-1.5",
                    for (index, option) in poll.options.iter().enumerate() {
                        {
                            let count = counts
                                .get(index)
                                .map(|members| members.len())
                                .unwrap_or(0);
                            let pct = if total > 0 {
                                (count * 100) / total
                            } else {
                                0
                            };
                            let idx = index as u16;
                            let is_selected = my_votes.contains(&idx);
                            let next_choices = if poll.multiselect {
                                let mut next = my_votes.clone();
                                if let Some(pos) = next.iter().position(|&v| v == idx) {
                                    next.remove(pos);
                                } else {
                                    next.push(idx);
                                    next.sort_unstable();
                                }
                                next
                            } else {
                                vec![idx]
                            };
                            let option = option.clone();
                            let btn_class = if is_selected {
                                "relative overflow-hidden flex items-center justify-between gap-3 px-3 py-1.5 rounded-lg border border-accent bg-accent/10 text-sm text-text hover:bg-panel disabled:opacity-60"
                            } else {
                                "relative overflow-hidden flex items-center justify-between gap-3 px-3 py-1.5 rounded-lg border border-border text-sm text-text hover:bg-panel disabled:opacity-60"
                            };
                            rsx! {
                                button {
                                    key: "poll-choice-{index}",
                                    r#type: "button",
                                    class: "{btn_class}",
                                    disabled: closed,
                                    onclick: move |_| {
                                        let choices = next_choices.clone();
                                        spawn(async move {
                                            let _ = topic_contract::vote(
                                                owner,
                                                topic_id,
                                                part,
                                                poll_id,
                                                choices,
                                            )
                                            .await;
                                        });
                                    },
                                    if total > 0 {
                                        div {
                                            class: "absolute inset-y-0 left-0 bg-accent/15 pointer-events-none",
                                            style: "width: {pct}%;",
                                        }
                                    }
                                    span { class: "relative z-10", "{option}" }
                                    span { class: "relative z-10 text-xs text-text-muted",
                                        if total > 0 {
                                            "{count} ({pct}%)"
                                        } else {
                                            "{count}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                p { class: "mt-2 text-[11px] text-text-muted",
                    "{total} votes"
                    if !my_votes.is_empty() { " · Vote recorded." }
                    if poll.multiselect { " · multiple choice" }
                    if closed { " · closed" }
                    if edited { " · edited" }
                }
            }
        }
    }
}
