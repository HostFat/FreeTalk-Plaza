//! "About FreeTalk Plaza" panel: name, what the app is, and the build/deployment
//! details a user needs when reporting a problem.

use crate::components::app::ABOUT_MODAL;
use dioxus::prelude::*;
use web_sys::window;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_TIMESTAMP: &str = env!("BUILD_TIMESTAMP_ISO");
const COMMIT: &str = env!("GIT_COMMIT_HASH");
const COMMIT_COUNT: &str = env!("GIT_COMMIT_COUNT");
const COMMIT_DATE: &str = env!("GIT_COMMIT_DATE");

/// `id` of the web-container contract when the app is served by a Freenet node,
/// i.e. from `/v1/contract/web/<id>/...`; `None` for a local dev build.
fn site_contract_id() -> Option<String> {
    let path = window()?.location().pathname().ok()?;
    let rest = path.split("/v1/contract/web/").nth(1)?;
    let id: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

#[component]
pub fn AboutModal() -> Element {
    if !*ABOUT_MODAL.read() {
        return rsx! {};
    }

    let node = window()
        .and_then(|w| w.location().host().ok())
        .unwrap_or_else(|| "unknown".to_string());
    let site = site_contract_id();
    let site_label = site.clone().unwrap_or_else(|| "local".to_string());

    rsx! {
        div {
            class: "fixed inset-0 z-50 flex items-center justify-center p-4",
            tabindex: "0",
            onkeydown: move |evt: KeyboardEvent| {
                if evt.key() == Key::Escape {
                    evt.prevent_default();
                    *ABOUT_MODAL.write() = false;
                }
            },
            div {
                class: "absolute inset-0 bg-black/50",
                onclick: move |_| *ABOUT_MODAL.write() = false,
            }
            div {
                class: "relative bg-panel rounded-xl shadow-xl max-w-md w-full",
                onclick: move |e| e.stop_propagation(),

                div { class: "flex items-center gap-3 px-6 py-5 border-b border-border",
                    img {
                        src: asset!("/assets/plaza_logo.svg"),
                        class: "w-12 h-12",
                        alt: "",
                    }
                    div { class: "flex flex-col",
                        span { class: "text-lg font-semibold text-text", "FreeTalk Plaza" }
                        span { class: "text-xs tracking-wide text-text-muted",
                            "Forums on Freenet"
                        }
                    }
                }

                div { class: "px-6 py-5 space-y-3 text-sm text-text-muted",
                    p { "Boards, categories and posts live in Freenet contracts, so no server holds them and no account is needed." }
                    p { class: "text-amber-200",
                        "Development preview: things can break and data can be lost without notice. Do not rely on it for long-term content."
                    }
                    dl { class: "grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 font-mono text-xs",
                        dt { class: "text-text-muted", "Version" }
                        dd { class: "text-text", "{VERSION}" }
                        dt { class: "text-text-muted", "Build" }
                        dd { class: "text-text", "#{COMMIT_COUNT} · {COMMIT} · {COMMIT_DATE}" }
                        dt { class: "text-text-muted", "Built" }
                        dd { class: "text-text", "{BUILD_TIMESTAMP}" }
                        dt { class: "text-text-muted", "Node" }
                        dd { class: "text-text break-all", "{node}" }
                        if let Some(site) = site {
                            dt { class: "text-text-muted", "Site" }
                            dd { class: "text-text break-all", "{site}" }
                        }
                    }
                    p { class: "text-xs",
                        "To check whether this site is current, compare the commit above with the latest commit in the repository."
                    }
                    p { class: "text-xs",
                        "Source code: "
                        a {
                            href: "https://github.com/HostFat/FreeTalk-Plaza",
                            target: "_blank",
                            rel: "noopener noreferrer",
                            class: "text-accent hover:underline break-all",
                            "github.com/HostFat/FreeTalk-Plaza"
                        }
                    }
                }

                div { class: "px-6 py-4 border-t border-border flex items-center justify-between gap-3",
                    button {
                        class: "px-4 py-2 bg-surface hover:bg-surface-hover text-text text-sm rounded-lg transition-colors",
                        onclick: move |_| {
                            let details = format!(
                                "FreeTalk Plaza {VERSION}\nBuild #{COMMIT_COUNT} · {COMMIT} · {COMMIT_DATE}\nBuilt {BUILD_TIMESTAMP}\nNode {node}\nSite {site_label}"
                            );
                            crate::util::copy_to_clipboard(&details);
                        },
                        "Copy details"
                    }
                    button {
                        class: "px-4 py-2 bg-surface hover:bg-surface-hover text-text text-sm rounded-lg transition-colors",
                        onclick: move |_| *ABOUT_MODAL.write() = false,
                        "Close"
                    }
                }
            }
        }
    }
}
