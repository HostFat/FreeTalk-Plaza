//! Reason picker for reporting a post.

use crate::components::app::REPORT_TARGET;
use crate::util::message_actions::ActionContext;
use crate::util::moderation_queue;
use dioxus::prelude::*;
use plaza_core::board_state::reports::ReportReason;

#[component]
pub fn ReportModal() -> Element {
    let target = REPORT_TARGET.read().clone();
    let Some(target) = target else {
        return rsx! {};
    };
    let mut error = use_signal(|| None::<String>);

    let close = move |_| {
        REPORT_TARGET.with_mut(|target| *target = None);
    };

    let mut send = move |reason: ReportReason| {
        let Some(ctx) = ActionContext::from_current_board() else {
            return;
        };
        match moderation_queue::report_post(&ctx, target, reason) {
            Ok(()) => {
                REPORT_TARGET.with_mut(|target| *target = None);
                error.set(None);
            }
            Err(e) => error.set(Some(e)),
        }
    };

    rsx! {
        div {
            class: "fixed inset-0 bg-black/50 flex items-center justify-center z-50",
            onclick: close,
            div {
                class: "bg-panel rounded-xl shadow-xl w-full max-w-sm mx-4",
                onclick: move |evt| evt.stop_propagation(),
                div { class: "px-5 py-4 border-b border-border",
                    h2 { class: "text-base font-semibold text-text", "Report this post" }
                    p { class: "text-xs text-text-muted mt-1",
                        "A moderator will see the reason. Reports are public board metadata."
                    }
                }
                div { class: "p-4 space-y-2",
                    for reason in [
                        ReportReason::Spam,
                        ReportReason::Abuse,
                        ReportReason::OffTopic,
                        ReportReason::Illegal,
                        ReportReason::Other,
                    ] {
                        button {
                            r#type: "button",
                            class: "w-full text-left px-3 py-2 bg-surface hover:bg-surface-hover text-text text-sm rounded-lg transition-colors",
                            onclick: move |_| send(reason),
                            "{reason.label()}"
                        }
                    }
                    if let Some(message) = error.read().as_ref() {
                        p { class: "text-xs text-red-400 pt-1", "{message}" }
                    }
                }
                div { class: "px-4 pb-4",
                    button {
                        r#type: "button",
                        class: "w-full px-3 py-2 text-text-muted hover:text-text text-sm rounded-lg transition-colors",
                        onclick: close,
                        "Cancel"
                    }
                }
            }
        }
    }
}
