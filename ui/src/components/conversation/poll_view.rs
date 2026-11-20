//! Poll options, counts and voting.

use crate::components::app::{BOARDS, CURRENT_BOARD};
use crate::components::conversation::PollData;
use crate::util::format_utc_as_local_time;
use crate::util::messaging::send_poll_vote;
use dioxus::prelude::*;
use plaza_core::board_state::content::PollVoteV1;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;
use wasm_bindgen_futures::spawn_local;

#[component]
pub fn PollView(
    poll: PollData,
    poll_id: MessageId,
    self_member_id: MemberId,
    /// The current identity wrote this poll and no vote exists yet.
    #[props(default)]
    is_author: bool,
) -> Element {
    let now = chrono::Utc::now().timestamp_millis();
    let closed = poll.is_closed(now);
    let initial = poll
        .my_ballot(self_member_id)
        .map(|ballot| ballot.options.clone())
        .unwrap_or_default();
    let generation = poll
        .my_ballot(self_member_id)
        .map(|ballot| ballot.generation + 1)
        .unwrap_or(1);
    let mut selected = use_signal(move || initial);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut editing = use_signal(|| false);
    let mut edit_options = use_signal(|| poll.options.clone());
    let mut edit_results = use_signal(|| poll.results_visibility);
    let edit_results_value = match *edit_results.read() {
        plaza_core::board_state::content::PollResultsVisibility::Always => "always",
        plaza_core::board_state::content::PollResultsVisibility::AfterVote => "vote",
        plaza_core::board_state::content::PollResultsVisibility::AfterClose => "close",
    }
    .to_string();

    let counts = poll.counts();
    let total = poll.counted().count();
    let has_voted = poll.my_ballot(self_member_id).is_some();
    let show_results = match poll.results_visibility {
        plaza_core::board_state::content::PollResultsVisibility::Always => true,
        plaza_core::board_state::content::PollResultsVisibility::AfterVote => {
            has_voted || closed
        }
        plaza_core::board_state::content::PollResultsVisibility::AfterClose => closed,
    };
    let polls = poll.clone();
    let multiselect = polls.multiselect;
    let edit_start_options = polls.options.clone();

    let mut vote = move |_| {
        if *busy.peek() || closed {
            return;
        }
        let options = selected.peek().clone();
        if options.is_empty() {
            return;
        }
        let Some(board_data) = CURRENT_BOARD
            .read()
            .owner_key
            .and_then(|key| BOARDS.read().map.get(&key).cloned())
        else {
            return;
        };
        if let Err(message) = board_data.ensure_can_write() {
            error.set(Some(message));
            return;
        }
        let posting = board_data.posting_secret_for(&poll_id);
        let category_id = posting.as_ref().map(|(id, _, _)| *id);
        let vote = PollVoteV1 {
            poll: poll_id,
            options,
            generation,
            created_at: chrono::Utc::now().timestamp_millis(),
        };
        busy.set(true);
        spawn_local(async move {
            match send_poll_vote(
                board_data.owner_vk,
                board_data.board_key(),
                board_data.self_sk.clone(),
                board_data.board_state.clone(),
                board_data.is_private(),
                board_data
                    .get_secret()
                    .map(|(secret, version)| (*secret, version)),
                posting,
                category_id,
                vote,
            )
            .await
            {
                Ok(()) => {
                    error.set(None);
                    crate::components::app::toasts::show(
                        "Vote recorded. Syncing with the network…",
                    );
                }
                Err(message) => {
                    crate::components::app::toasts::show_error(format!(
                        "Could not record the vote: {message}"
                    ));
                    error.set(Some(message));
                }
            }
            busy.set(false);
        });
    };

    rsx! {
        div { class: "mt-3 border border-border rounded-lg p-3 bg-surface/40 space-y-2",
            div { class: "flex flex-wrap items-center justify-between gap-2",
                div { class: "flex items-center gap-2",
                    span { class: "text-sm font-medium text-text", "Poll" }
                    if is_author && !closed {
                        button {
                            r#type: "button",
                            class: "text-xs text-accent hover:underline",
                            onclick: {
                                let options = edit_start_options.clone();
                                move |_| {
                                    edit_options.set(options.clone());
                                    edit_results.set(polls.results_visibility);
                                    editing.set(true);
                                }
                            },
                            "Edit poll"
                        }
                    }
                }
                span { class: "text-xs text-text-muted",
                    if closed {
                        "Closed"
                    } else if let Some(closes) = polls.closes_at {
                        "Closes {format_utc_as_local_time(closes)}"
                    } else {
                        "No deadline"
                    }
                    if show_results {
                        " · {total} "
                        if total == 1 { "vote" } else { "votes" }
                    }
                }
            }
            if editing() {
                div { class: "border-t border-border pt-2 space-y-2",
                    p { class: "text-xs text-text-muted", "Options can change after voting; existing votes for remaining options are kept." }
                    for (index, option) in edit_options.read().iter().enumerate() {
                        div { key: "{index}", class: "flex items-center gap-2",
                            input {
                                r#type: "text",
                                class: "flex-1 px-2 py-1 bg-panel border border-border rounded text-sm text-text",
                                value: "{option}",
                                oninput: move |event| {
                                    edit_options.with_mut(|options| {
                                        if let Some(slot) = options.get_mut(index) {
                                            *slot = event.value();
                                        }
                                    });
                                },
                            }
                            if edit_options.read().len() > 2 {
                                button {
                                    r#type: "button",
                                    class: "px-2 text-text-muted hover:text-text",
                                    onclick: move |_| {
                                        edit_options.with_mut(|options| {
                                            if index < options.len() {
                                                options.remove(index);
                                            }
                                        });
                                    },
                                    "×"
                                }
                            }
                        }
                    }
                    div { class: "flex flex-wrap items-center gap-2 text-xs",
                        button {
                            r#type: "button",
                            class: "px-2 py-1 bg-panel border border-border rounded text-text",
                            onclick: move |_| edit_options.with_mut(|options| options.push(String::new())),
                            "+ Option"
                        }
                        label { class: "flex items-center gap-1 text-text-muted",
                            "Results"
                            select {
                                class: "px-2 py-1 bg-panel border border-border rounded text-text",
                                value: "{edit_results_value}",
                                onchange: move |event| {
                                    use plaza_core::board_state::content::PollResultsVisibility;
                                    edit_results.set(match event.value().as_str() {
                                        "vote" => PollResultsVisibility::AfterVote,
                                        "close" => PollResultsVisibility::AfterClose,
                                        _ => PollResultsVisibility::Always,
                                    });
                                },
                                option { value: "always", "Always" }
                                option { value: "vote", "After voting" }
                                option { value: "close", "After close" }
                            }
                        }
                    }
                    div { class: "flex items-center gap-2",
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-xs rounded-lg",
                            onclick: move |_| {
                                use plaza_core::board_state::content::PollContentV1;
                                let content = PollContentV1::new(
                                    polls.title.clone(),
                                    polls.description.clone(),
                                    edit_options.read().clone(),
                                    polls.closes_at,
                                    polls.multiselect,
                                )
                                .with_results_visibility(*edit_results.read());
                                if let Err(message) = content.validate() {
                                    error.set(Some(message));
                                    return;
                                }
                                let Some(ctx) = crate::util::message_actions::ActionContext::from_current_board() else {
                                    return;
                                };
                                let id = poll_id.clone();
                                spawn_local(async move {
                                    crate::util::message_actions::edit_poll(ctx, id, content).await;
                                });
                                editing.set(false);
                            },
                            "Save"
                        }
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 bg-panel border border-border text-text text-xs rounded-lg",
                            onclick: move |_| editing.set(false),
                            "Cancel"
                        }
                    }
                    if let Some(message) = error.read().as_ref() {
                        p { class: "text-xs text-red-400", "{message}" }
                    }
                }
            }
            for (index, option) in polls.options.iter().enumerate() {
                {
                    let index = index as u16;
                    let count = counts.get(index as usize).copied().unwrap_or(0);
                    let percent = if total > 0 { count * 100 / total } else { 0 };
                    let chosen = selected.read().contains(&index);
                    let can_click = !closed && !*busy.read();
                    rsx! {
                        button {
                            r#type: "button",
                            class: if chosen && can_click {
                                "w-full text-left rounded-lg border border-accent/60 bg-accent/10 px-3 py-2 transition-colors"
                            } else if can_click {
                                "w-full text-left rounded-lg border border-border hover:border-accent/50 px-3 py-2 transition-colors"
                            } else {
                                "w-full text-left rounded-lg border border-border px-3 py-2"
                            },
                            disabled: !can_click,
                            onclick: move |_| {
                                if multiselect {
                                    selected.with_mut(|values| {
                                        if let Some(position) = values.iter().position(|v| *v == index) {
                                            values.remove(position);
                                        } else {
                                            values.push(index);
                                        }
                                    });
                                } else {
                                    selected.set(vec![index]);
                                }
                            },
                            div { class: "flex items-center justify-between text-sm",
                                span { class: "text-text", "{option}" }
                                if show_results {
                                    span { class: "text-xs text-text-muted", "{count} · {percent}%" }
                                }
                            }
                            if show_results {
                                div { class: "mt-1 h-1.5 bg-panel rounded overflow-hidden",
                                    div {
                                        class: "h-full bg-accent/70",
                                        style: "width: {percent}%",
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "flex items-center gap-3",
                if closed {
                    span { class: "text-xs text-text-muted", "Voting is closed." }
                } else {
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-xs font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed",
                        disabled: *busy.read() || selected.read().is_empty(),
                        onclick: move |evt| vote(evt),
                        if has_voted { "Change vote" } else { "Vote" }
                    }
                    if polls.multiselect {
                        span { class: "text-xs text-text-muted", "Multiple answers allowed" }
                    }
                }
                if !show_results {
                    span { class: "text-xs text-text-muted",
                        if matches!(
                            poll.results_visibility,
                            plaza_core::board_state::content::PollResultsVisibility::AfterVote
                        ) {
                            "Results appear after you vote."
                        } else {
                            "Results appear when the poll closes."
                        }
                    }
                }
                if let Some(message) = error.read().as_ref() {
                    span { class: "text-xs text-red-400", "{message}" }
                }
            }
        }
    }
}
