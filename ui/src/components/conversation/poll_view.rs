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
pub fn PollView(poll: PollData, poll_id: MessageId, self_member_id: MemberId) -> Element {
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

    let counts = poll.counts();
    let total = poll.counted().count();
    let has_voted = poll.my_ballot(self_member_id).is_some();
    let polls = poll.clone();
    let multiselect = polls.multiselect;

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
            send_poll_vote(
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
            .await;
            busy.set(false);
            error.set(None);
        });
    };

    rsx! {
        div { class: "mt-3 border border-border rounded-lg p-3 bg-surface/40 space-y-2",
            div { class: "flex flex-wrap items-center justify-between gap-2",
                span { class: "text-sm font-medium text-text", "Poll" }
                span { class: "text-xs text-text-muted",
                    if closed {
                        "Closed"
                    } else if let Some(closes) = polls.closes_at {
                        "Closes {format_utc_as_local_time(closes)}"
                    } else {
                        "No deadline"
                    }
                    " · {total} "
                    if total == 1 { "vote" } else { "votes" }
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
                                span { class: "text-xs text-text-muted", "{count} · {percent}%" }
                            }
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
                if let Some(message) = error.read().as_ref() {
                    span { class: "text-xs text-red-400", "{message}" }
                }
            }
        }
    }
}
