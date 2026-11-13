use crate::components::app::{BOARDS, CURRENT_BOARD, CURRENT_CATEGORY};
use crate::util::messaging::{send_category, send_group};
use dioxus::prelude::*;
use plaza_core::board_state::content::validate_icon;
use plaza_core::board_state::message::MessageId;
use plaza_core::board_state::roles::RoleId;
use wasm_bindgen_futures::spawn_local;

/// Global signal for category creation modal
pub static CREATE_CATEGORY_MODAL: GlobalSignal<CreateCategoryModalSignal> =
    Global::new(|| CreateCategoryModalSignal {
        show: false,
        parent_category_id: None,
        is_group: false,
        parent_is_group: false,
    });

pub struct CreateCategoryModalSignal {
    pub show: bool,
    pub parent_category_id: Option<MessageId>,
    /// Create a homepage group instead of a section
    pub is_group: bool,
    /// The parent is a group, so this is a section and not a subsection
    pub parent_is_group: bool,
}

/// Color presets for category selection
const COLOR_PRESETS: &[(&str, &str)] = &[
    ("#6366f1", "Indigo"),
    ("#8b5cf6", "Violet"),
    ("#ec4899", "Pink"),
    ("#ef4444", "Red"),
    ("#f97316", "Orange"),
    ("#eab308", "Yellow"),
    ("#22c55e", "Green"),
    ("#14b8a6", "Teal"),
    ("#0ea5e9", "Sky"),
    ("#6b7280", "Gray"),
];

#[component]
pub fn CategoryCreateModal() -> Element {
    let mut name = use_signal(String::new);
    let mut description = use_signal(String::new);
    let mut icon = use_signal(String::new);
    let mut color = use_signal(|| COLOR_PRESETS[0].0.to_string());
    let mut error_msg = use_signal(|| None::<String>);
    let mut is_creating = use_signal(|| false);
    let mut selected_roles = use_signal(Vec::<RoleId>::new);
    let mut hidden = use_signal(|| false);
    let mut selected_group = use_signal(|| None::<MessageId>);

    let modal_state = CREATE_CATEGORY_MODAL.read();
    let is_open = modal_state.show;
    let is_group = modal_state.is_group;
    let parent_is_group = modal_state.parent_is_group;
    let parent_id = modal_state.parent_category_id.clone();
    let parent_id_for_closure = parent_id.clone();
    let has_parent = parent_id.is_some();

    if !is_open {
        return rsx! {};
    }

    // Check if user can create categories and list the roles they can restrict to
    let (can_create, is_owner, roles, groups) = {
        let current_board = CURRENT_BOARD.read();
        if let Some(key) = current_board.owner_key {
            let boards = BOARDS.read();
            if let Some(board_data) = boards.map.get(&key) {
                let roles = board_data
                    .board_state
                    .roles
                    .roles
                    .iter()
                    .filter(|role| !role.role.deleted)
                    .map(|role| (role.role.id, role.role.name.clone()))
                    .collect::<Vec<_>>();
                let groups = board_data
                    .board_state
                    .recent_messages
                    .messages
                    .iter()
                    .filter_map(|message| {
                        let category = board_data
                            .readable_category(&message.id(), &message.message.content)?;
                        (category.is_group && category.parent_category_id.is_none())
                            .then(|| (message.id(), category.name))
                    })
                    .collect::<Vec<_>>();
                (
                    board_data.can_create_categories(),
                    board_data.self_sk.verifying_key() == board_data.owner_vk,
                    roles,
                    groups,
                )
            } else {
                (false, false, Vec::new(), Vec::new())
            }
        } else {
            (false, false, Vec::new(), Vec::new())
        }
    };

    if !can_create {
        return rsx! {
            // Backdrop
            div {
                class: "fixed inset-0 bg-black/50 z-40",
                onclick: move |_| {
                    CREATE_CATEGORY_MODAL.with_mut(|modal| {
                        modal.show = false;
                        modal.is_group = false;
                        modal.parent_is_group = false;
                    });
                }
            }
            // Error modal
            div { class: "fixed inset-0 z-50 flex items-center justify-center p-4",
                div {
                    class: "bg-panel rounded-xl shadow-xl max-w-md w-full p-6 text-center",
                    onclick: move |e| e.stop_propagation(),
                    h2 { class: "text-lg font-semibold text-text mb-4", "Permission Denied" }
                    p { class: "text-text-muted mb-4",
                        "Only board owners and admins can create sections and groups."
                    }
                    button {
                        class: "px-4 py-2 bg-accent hover:bg-accent/80 text-white rounded-lg transition-colors",
                        onclick: move |_| {
                            CREATE_CATEGORY_MODAL.with_mut(|modal| {
                                modal.show = false;
                                modal.is_group = false;
                        modal.parent_is_group = false;
                            });
                        },
                        "Close"
                    }
                }
            }
        };
    }

    let create_category = move |_| {
        let name_val = name.read().trim().to_string();
        if name_val.is_empty() {
            error_msg.set(Some("Category name cannot be empty".to_string()));
            return;
        }

        if name_val.len() > 50 {
            error_msg.set(Some(
                "Category name must be 50 characters or less".to_string(),
            ));
            return;
        }

        let icon_val = {
            let ic = icon.read().trim().to_string();
            if ic.is_empty() {
                None
            } else {
                if let Err(e) = validate_icon(&ic) {
                    error_msg.set(Some(e));
                    return;
                }
                Some(ic)
            }
        };

        error_msg.set(None);
        is_creating.set(true);

        let description_val = {
            let desc = description.read().trim().to_string();
            if desc.is_empty() {
                None
            } else {
                Some(desc)
            }
        };

        let color_val = color.read().clone();
        let parent_id_val = if is_group {
            None
        } else if has_parent {
            parent_id_for_closure.clone()
        } else {
            (*selected_group.read()).clone()
        };
        let roles_val = selected_roles.read().clone();
        let hidden_val = *hidden.read();
        let creating_group = is_group;

        spawn_local(async move {
            let result = if creating_group {
                send_group(name_val, description_val, icon_val, color_val).await
            } else {
                send_category(
                    name_val,
                    description_val,
                    icon_val,
                    color_val,
                    parent_id_val,
                    roles_val,
                    hidden_val,
                )
                .await
            };
            match result {
                Ok(()) => {
                    // Reset and close modal
                    name.set(String::new());
                    description.set(String::new());
                    icon.set(String::new());
                    color.set(COLOR_PRESETS[0].0.to_string());
                    selected_roles.set(Vec::new());
                    hidden.set(false);
                    selected_group.set(None);
                    CREATE_CATEGORY_MODAL.with_mut(|modal| {
                        modal.show = false;
                        modal.parent_category_id = None;
                        modal.is_group = false;
                        modal.parent_is_group = false;
                    });
                }
                Err(e) => {
                    let kind = if creating_group { "group" } else { "section" };
                    error_msg.set(Some(format!("Failed to create {}: {}", kind, e)));
                }
            }
            is_creating.set(false);
        });
    };

    let title = if is_group {
        "Create Group"
    } else if has_parent && !parent_is_group {
        "Create Subsection"
    } else {
        "Create Section"
    };

    // Get parent category name for display
    let parent_category_name = if has_parent {
        CURRENT_CATEGORY.read().category_name.clone()
    } else {
        None
    };

    rsx! {
        // Backdrop
        div {
            class: "fixed inset-0 bg-black/50 z-40",
            onclick: move |_| {
                CREATE_CATEGORY_MODAL.with_mut(|modal| {
                    modal.show = false;
                    modal.parent_category_id = None;
                    modal.is_group = false;
                        modal.parent_is_group = false;
                });
            }
        }

        // Modal
        div { class: "fixed inset-0 z-50 flex items-center justify-center p-4",
            div {
                class: "bg-panel rounded-xl shadow-xl max-w-md w-full",
                onclick: move |e| e.stop_propagation(),

                // Header
                div { class: "px-6 py-4 border-b border-border",
                    h2 { class: "text-lg font-semibold text-text", "{title}" }
                }

                // Body
                div { class: "px-6 py-4 space-y-4",
                    // Error message
                    if let Some(err) = error_msg.read().as_ref() {
                        div { class: "p-3 bg-error-bg border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-400",
                            "{err}"
                        }
                    }

                    // Parent category indicator
                    if let Some(parent_name) = parent_category_name.as_ref() {
                        div { class: "flex items-center gap-2 px-3 py-2 bg-surface border-l-2 border-accent rounded text-sm text-text-muted",
                            span { class: "flex-1",
                                span { class: "font-medium", "📁 Creating in: " }
                                "{parent_name}"
                            }
                        }
                    }

                    // Name input
                    div {
                        label { class: "block text-sm font-medium text-text mb-1", "Name *" }
                        input {
                            class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent",
                            value: "{name}",
                            placeholder: "Category name",
                            maxlength: 50,
                            oninput: move |evt| name.set(evt.value().replace(['\n', '\r'], ""))
                        }
                    }

                    // Description input
                    div {
                        label { class: "block text-sm font-medium text-text mb-1", "Description" }
                        textarea {
                            class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent resize-y min-h-[80px]",
                            value: "{description}",
                            placeholder: "Optional description",
                            oninput: move |evt| description.set(evt.value())
                        }
                    }

                    // Icon input
                    div {
                        label { class: "block text-sm font-medium text-text mb-1", "Icon (emoji)" }
                        div { class: "flex items-center gap-3",
                            input {
                                class: "flex-1 px-3 py-2 bg-surface border border-border rounded-lg text-text placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent",
                                value: "{icon}",
                                placeholder: "Type an emoji (optional)",
                                oninput: move |evt| icon.set(evt.value())
                            }
                            // Preview
                            div {
                                class: "w-10 h-10 flex items-center justify-center bg-surface rounded-lg border border-border text-2xl",
                                {
                                    let ic = icon.read().clone();
                                    if ic.is_empty() { "📁".to_string() } else { ic }
                                }
                            }
                        }
                    }

                    // Group picker for a new top-level section
                    if !is_group && !has_parent && !groups.is_empty() {
                        div {
                            label { class: "block text-sm font-medium text-text mb-1", "Group" }
                            select {
                                class: "w-full px-3 py-2 bg-surface border border-border rounded-lg text-text text-sm",
                                value: (*selected_group.read())
                                    .as_ref()
                                    .map(|id| id.to_string())
                                    .unwrap_or_default(),
                                onchange: move |evt| {
                                    let value = evt.value();
                                    selected_group.set(if value.is_empty() {
                                        None
                                    } else {
                                        value.parse::<MessageId>().ok()
                                    });
                                },
                                option { value: "", "Ungrouped" }
                                for (group_id, group_name) in groups.iter() {
                                    option {
                                        value: "{group_id}",
                                        "{group_name}"
                                    }
                                }
                            }
                        }
                    }

                    // Color picker
                    div {
                        label { class: "block text-sm font-medium text-text mb-2", "Color *" }
                        div { class: "flex flex-wrap gap-2",
                            {COLOR_PRESETS.iter().map(|(hex, label)| {
                                let hex = *hex;
                                let is_selected = *color.read() == hex;
                                rsx! {
                                    button {
                                        key: "{hex}",
                                        class: if is_selected {
                                            "w-8 h-8 rounded-full ring-2 ring-offset-2 ring-offset-panel ring-text relative flex items-center justify-center"
                                        } else {
                                            "w-8 h-8 rounded-full hover:scale-110 transition-transform"
                                        },
                                        style: "background-color: {hex};",
                                        title: "{label}",
                                        onclick: move |_| color.set(hex.to_string()),
                                        if is_selected {
                                            span { class: "text-white text-sm font-bold drop-shadow-[0_1px_1px_rgba(0,0,0,0.5)]", "✓" }
                                        }
                                    }
                                }
                            })}
                        }
                    }

                    // Restricted visibility: owner only, and only when roles exist
                    if is_owner && !is_group && !roles.is_empty() {
                        div {
                            label { class: "block text-sm font-medium text-text mb-2", "Visible to" }
                            p { class: "text-xs text-text-muted mb-2",
                                "Select roles to keep this category private. Leave empty for everyone."
                            }
                            div { class: "flex flex-wrap gap-2",
                                {roles.iter().map(|(id, role_name)| {
                                    let id = *id;
                                    let selected = selected_roles.read().contains(&id);
                                    let role_name = role_name.clone();
                                    rsx! {
                                        button {
                                            key: "{id:?}",
                                            r#type: "button",
                                            class: if selected {
                                                "px-3 py-1.5 text-sm rounded-full bg-accent text-white"
                                            } else {
                                                "px-3 py-1.5 text-sm rounded-full bg-surface border border-border text-text-muted hover:text-text"
                                            },
                                            onclick: move |_| {
                                                let mut current = selected_roles.write();
                                                if current.contains(&id) {
                                                    current.retain(|role| *role != id);
                                                } else {
                                                    current.push(id);
                                                }
                                            },
                                            "{role_name}"
                                        }
                                    }
                                })}
                            }
                            if !selected_roles.read().is_empty() {
                                label { class: "flex items-center gap-2 mt-3 text-sm text-text cursor-pointer",
                                    input {
                                        r#type: "checkbox",
                                        checked: *hidden.read(),
                                        onchange: move |evt| hidden.set(evt.checked()),
                                    }
                                    "Hide from members without access"
                                }
                                p { class: "text-xs text-text-muted mt-1",
                                    "The name and posts are encrypted with a key shared with the selected roles."
                                }
                            }
                        }
                    } else if !is_owner && !roles.is_empty() {
                        p { class: "text-xs text-text-muted",
                            "Only the owner can restrict a category to roles."
                        }
                    }
                }

                // Footer
                div { class: "px-6 py-4 border-t border-border flex justify-end gap-3",
                    button {
                        class: "px-4 py-2 text-sm text-text-muted hover:text-text hover:bg-surface rounded-lg transition-colors",
                        disabled: *is_creating.read(),
                        onclick: move |_| {
                            CREATE_CATEGORY_MODAL.with_mut(|modal| {
                                modal.show = false;
                                modal.parent_category_id = None;
                                modal.is_group = false;
                        modal.parent_is_group = false;
                            });
                        },
                        "Cancel"
                    }
                    button {
                        class: "px-4 py-2 text-sm bg-accent hover:bg-accent/80 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed",
                        disabled: *is_creating.read() || name.read().trim().is_empty(),
                        onclick: create_category,
                        if *is_creating.read() { "Creating..." } else { "Create" }
                    }
                }
            }
        }
    }
}
