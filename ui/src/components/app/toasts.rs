//! Small transient messages shown after an action.

use dioxus::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, PartialEq)]
pub enum ToastKind {
    Info,
    Error,
}

#[derive(Clone, PartialEq)]
pub struct Toast {
    pub id: u64,
    pub text: String,
    pub kind: ToastKind,
}

pub static TOASTS: GlobalSignal<Vec<Toast>> = Global::new(Vec::new);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Show a toast for a few seconds.
pub fn show(text: impl Into<String>) {
    push(text.into(), ToastKind::Info);
}

/// Show an error toast for a few seconds.
pub fn show_error(text: impl Into<String>) {
    push(text.into(), ToastKind::Error);
}

fn push(text: String, kind: ToastKind) {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    TOASTS.with_mut(|toasts| toasts.push(Toast { id, text, kind }));
    crate::util::safe_spawn_local(async move {
        crate::util::sleep(std::time::Duration::from_secs(6)).await;
        TOASTS.with_mut(|toasts| toasts.retain(|toast| toast.id != id));
    });
}

#[component]
pub fn ToastContainer() -> Element {
    rsx! {
        div { class: "fixed bottom-4 right-4 z-[100] flex flex-col gap-2 max-w-sm",
            for toast in TOASTS.read().iter() {
                div {
                    key: "{toast.id}",
                    class: match toast.kind {
                        ToastKind::Info => "px-4 py-2 rounded-lg bg-surface border border-border text-sm text-text shadow-lg",
                        ToastKind::Error => "px-4 py-2 rounded-lg bg-red-950 border border-red-500 text-sm text-red-200 shadow-lg",
                    },
                    "{toast.text}"
                }
            }
        }
    }
}
