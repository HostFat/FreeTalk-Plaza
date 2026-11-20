//! "About FreeTalk Plaza" panel: what the app is and the build/deployment
//! details a user needs when reporting a problem. Identities and backups live
//! in the device drawer so this panel stays informational.

use crate::components::app::ABOUT_MODAL;
use crate::components::device_drawer::{open as open_device, DeviceTab};
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
                class: "about-modal relative bg-panel rounded-xl shadow-xl max-w-lg w-full max-h-[90vh] overflow-y-auto",
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
                    p { "Boards, categories, topics and posts live in Freenet contracts, so no server holds them and no account is needed." }
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

                    // The device drawer holds the actions on local data, so
                    // this panel stays a short informational page.
                    button {
                        r#type: "button",
                        class: "w-full flex items-center gap-3 rounded-xl border border-border bg-surface/60 p-3 text-left hover:border-accent/60 hover:bg-surface transition-colors",
                        onclick: move |_| {
                            *ABOUT_MODAL.write() = false;
                            open_device(DeviceTab::Identities);
                        },
                        span { class: "text-lg", "👤" }
                        div { class: "flex flex-1 flex-col",
                            span { class: "text-sm font-medium text-text", "Identities and backup" }
                            span { class: "text-xs text-text-muted",
                                "Profiles, private-board keys and the local backup file."
                            }
                        }
                        span { class: "text-text-muted text-lg", "›" }
                    }

                    details { class: "border-t border-border pt-3",
                        summary { class: "text-sm text-text cursor-pointer",
                            "Contract versions and rekey"
                        }
                        div { class: "mt-2 space-y-2 text-xs text-text-muted",
                            p {
                                "The app bundle and each board contract are separate. A new build updates the web container state, so the site id above stays the same while the version and commit change."
                            }
                            ul { class: "list-disc pl-4 space-y-1",
                                li {
                                    "A board contract key comes from its wasm plus the board owner. Changing the board contract creates a new key; this client records the migration and the owner sends a signed upgrade pointer to the old contract."
                                }
                                li {
                                    "Profile and owner keys are local and are not part of the contract key, so they survive a rekey."
                                }
                                li {
                                    "Download a backup before deploying. After deploying, open the app once as the owner, let the sync chip settle, and check that the board opens from the new key."
                                }
                            }
                        }
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
                    div { class: "border-t border-border pt-3",
                        button {
                            r#type: "button",
                            class: "text-xs text-text-muted hover:text-text underline decoration-dotted",
                            title: "Test only: hides owner and admin controls in this tab until reload",
                            onclick: move |_| {
                                *crate::components::app::TEST_VIEW_MEMBER.write() = true;
                                *ABOUT_MODAL.write() = false;
                            },
                            "Preview member view"
                        }
                        p { class: "text-[11px] text-text-muted mt-1",
                            "Hides owner and admin controls in this tab until reload."
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
