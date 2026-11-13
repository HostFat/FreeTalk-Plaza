use crate::components::conversation::MessageData;
use dioxus::prelude::*;
use freenet_scaffold::util::FastHash;
use plaza_core::board_state::content::validate_icon;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;

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

/// Category edit payload for the edit handler
#[derive(Clone, Debug)]
pub struct CategoryEditData {
    pub message_id: MessageId,
    pub new_name: String,
    pub new_description: Option<String>,
    pub new_icon: Option<String>,
    pub new_color: String,
    /// `Some(parent)` moves the section; `None` keeps the current parent.
    pub new_parent: Option<Option<MessageId>>,
}

/// A card component for displaying a category in a grid
#[component]
pub fn CategoryCard(
    /// The category data
    category: MessageData,
    /// Self member ID for determining edit/delete permissions
    self_member_id: MemberId,
    /// Whether the current user is the board owner
    #[props(default)]
    is_owner: bool,
    /// Whether the current user is a board admin
    #[props(default)]
    is_admin: bool,
    /// Number of posts in this category and its subcategories
    #[props(default)]
    post_count: usize,
    /// Time and author of the newest post in this category
    #[props(default)]
    last_activity: Option<(String, String)>,
    /// Unread posts in this section
    #[props(default)]
    unread_count: usize,
    /// Groups show a "+ Section" action
    #[props(default)]
    on_new_section: Option<EventHandler<()>>,
    /// Group is collapsed for this user
    #[props(default)]
    collapsed: bool,
    /// Toggle the group collapse state
    #[props(default)]
    on_toggle_collapsed: Option<EventHandler<()>>,
    /// Child boards shown inside the section card on the home page
    #[props(default)]
    child_boards: Vec<(MessageId, String)>,
    /// Click handler for a child board name
    #[props(default)]
    on_child_click: Option<EventHandler<MessageId>>,
    /// Groups available for moving this section
    #[props(default)]
    groups: Vec<(MessageId, String)>,
    /// Top-level sections and sections inside a group can be moved
    #[props(default)]
    allow_group_change: bool,
    /// Click handler for navigation
    on_click: EventHandler<()>,
    /// Edit handler with full category data
    #[props(default)]
    on_edit: Option<EventHandler<CategoryEditData>>,
    /// Delete handler
    #[props(default)]
    on_request_delete: Option<EventHandler<MessageId>>,
) -> Element {
    let mut is_hovered = use_signal(|| false);
    let mut is_editing = use_signal(|| false);
    let mut edit_name = use_signal(String::new);
    let mut edit_description = use_signal(String::new);
    let mut edit_icon = use_signal(String::new);
    let mut edit_color = use_signal(String::new);
    let mut edit_group = use_signal(|| None::<MessageId>);
    let mut error_msg = use_signal(|| None::<String>);

    let icon = category.category_icon.as_deref().unwrap_or("📁");
    let name = category.category_name.as_deref().unwrap_or("Unnamed");
    let description = category.category_description.as_deref();
    let color = category.category_color.as_deref().unwrap_or("#6366f1");
    let current_parent_for_save = category.parent_category_id.clone();

    // Can edit if user is author, owner, or admin
    let is_author = category.author_id == self_member_id;
    let can_edit = is_author || is_owner || is_admin;
    let has_actions = can_edit && (on_edit.is_some() || on_request_delete.is_some());
    let msg_id = category.message_id.clone();

    rsx! {
        div {
            class: if category.is_group {
                if *is_editing.read() {
                    "bg-panel rounded-lg border border-border transition-colors cursor-pointer group relative"
                } else {
                    "rounded-lg transition-colors cursor-pointer group relative"
                }
            } else {
                "bg-panel rounded-lg border border-border overflow-hidden hover:border-accent/50 transition-colors cursor-pointer group relative"
            },
            onclick: move |_| {
                if !*is_editing.read() && !category.is_group {
                    on_click.call(())
                }
            },
            onmouseenter: move |_| is_hovered.set(true),
            onmouseleave: move |_| is_hovered.set(false),

            // Color accent bar at top (sections only)
            if !category.is_group {
                div {
                    class: "h-2",
                    style: if *is_editing.read() {
                        format!("background-color: {};", edit_color.read())
                    } else {
                        format!("background-color: {};", color)
                    },
                }
            }

            div {
                class: if category.is_group {
                    "px-1 py-1.5 border-b border-border mb-1"
                } else if has_actions {
                    "pl-4 pr-28 py-3"
                } else {
                    "px-4 py-3"
                },
                // Error message
                if let Some(err) = error_msg.read().as_ref() {
                    div { class: "mb-2 p-2 bg-red-100 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded text-xs text-red-700 dark:text-red-400",
                        "{err}"
                    }
                }

                // Icon and name row
                div { class: "flex items-center gap-3 mb-2",
                    if *is_editing.read() {
                        // Icon input
                        input {
                            class: "w-12 px-2 py-1 bg-surface border border-border rounded text-2xl text-center",
                            value: "{edit_icon}",
                            placeholder: "📁",
                            onclick: move |e| e.stop_propagation(),
                            oninput: move |e| edit_icon.set(e.value()),
                        }
                        // Name input
                        input {
                            class: "flex-1 px-2 py-1 bg-surface border border-border rounded text-text text-lg font-semibold",
                            value: "{edit_name}",
                            onclick: move |e| e.stop_propagation(),
                            oninput: move |e| edit_name.set(e.value()),
                        }
                    } else {
                        div { class: "flex items-center gap-3 min-w-0 w-full flex-wrap",
                            if category.is_group {
                                if let Some(handler) = on_toggle_collapsed.as_ref() {
                                    button {
                                        r#type: "button",
                                        class: "w-5 h-5 flex items-center justify-center rounded text-text-muted hover:text-text hover:bg-surface transition-colors flex-shrink-0",
                                        title: if collapsed { "Expand group" } else { "Collapse group" },
                                        onclick: {
                                            let handler = handler.clone();
                                            move |evt| {
                                                evt.stop_propagation();
                                                handler.call(());
                                            }
                                        },
                                        if collapsed { "▸" } else { "▾" }
                                    }
                                }
                            }
                            if !category.is_group {
                                span { class: "text-2xl flex-shrink-0", "{icon}" }
                            }
                            div { class: "flex-1 min-w-0 flex items-center gap-2",
                                h3 {
                                    class: if category.is_group {
                                        "text-sm font-semibold text-text-muted truncate min-w-0"
                                    } else {
                                        "text-base font-semibold text-text group-hover:text-accent transition-colors truncate min-w-0"
                                    },
                                    "{name}"
                                }
                                if !category.category_allowed_roles.is_empty() {
                                    span {
                                        class: "flex-shrink-0 text-xs px-2 py-0.5 rounded-full bg-surface border border-border text-text-muted",
                                        title: "Visible only to members of the selected roles",
                                        if category.category_locked { "🔒 Locked" } else { "🔒 Restricted" }
                                    }
                                }
                                if unread_count > 0 {
                                    span {
                                        class: "flex-shrink-0 text-xs px-2 py-0.5 rounded-full bg-accent/20 text-accent",
                                        "{unread_count} new"
                                    }
                                }
                                if let Some(desc) = description {
                                    span { class: "text-xs text-text-muted truncate min-w-0",
                                        "{desc}"
                                    }
                                }
                            }
                            div { class: "flex items-center gap-2 flex-shrink-0 text-right text-xs text-text-muted",
                                if !category.is_group {
                                    div {
                                        p {
                                            if post_count == 1 {
                                                "1 post"
                                            } else {
                                                "{post_count} posts"
                                            }
                                        }
                                        if let Some((author, time)) = last_activity.clone() {
                                            p { class: "mt-0.5", "{time} by {author}" }
                                        }
                                    }
                                }
                                if category.is_group {
                                    if let Some(handler) = on_new_section.as_ref() {
                                        button {
                                            r#type: "button",
                                            class: "px-2 py-1 rounded bg-accent/10 text-accent hover:bg-accent/20",
                                            title: "Create a section in this group",
                                            onclick: {
                                                let handler = handler.clone();
                                                move |evt| {
                                                    evt.stop_propagation();
                                                    handler.call(());
                                                }
                                            },
                                            "+ Section"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Description and color picker when editing
                if *is_editing.read() {
                    // Description
                    textarea {
                        class: "w-full px-2 py-1 bg-surface border border-border rounded text-sm text-text resize-none mb-2",
                        rows: 2,
                        value: "{edit_description}",
                        placeholder: "Description (optional)",
                        onclick: move |e| e.stop_propagation(),
                        oninput: move |e| edit_description.set(e.value()),
                    }

                    // Color picker
                    div { class: "mb-2",
                        label { class: "block text-xs font-medium text-text-muted mb-1", "Color" }
                        div { class: "flex flex-wrap gap-2",
                            {COLOR_PRESETS.iter().map(|(hex, label)| {
                                let hex = *hex;
                                let is_selected = *edit_color.read() == hex;
                                rsx! {
                                    button {
                                        r#type: "button",
                                        key: "{hex}",
                                        class: if is_selected {
                                            "w-8 h-8 rounded-full ring-2 ring-offset-2 ring-offset-panel ring-text relative flex items-center justify-center"
                                        } else {
                                            "w-8 h-8 rounded-full hover:scale-110 transition-transform"
                                        },
                                        style: "background-color: {hex};",
                                        title: "{label}",
                                        onclick: move |e| {
                                            e.stop_propagation();
                                            edit_color.set(hex.to_string());
                                        },
                                        if is_selected {
                                            span { class: "text-white text-sm font-bold drop-shadow-[0_1px_1px_rgba(0,0,0,0.5)]", "✓" }
                                        }
                                    }
                                }
                            })}
                        }
                    }

                    // Move the section to another group
                    if allow_group_change {
                        div { class: "mb-2",
                            label { class: "block text-xs font-medium text-text-muted mb-1", "Group" }
                            select {
                                class: "w-full px-2 py-1 bg-surface border border-border rounded text-sm text-text",
                                value: (*edit_group.read())
                                    .as_ref()
                                    .map(|id| id.0 .0.to_string())
                                    .unwrap_or_default(),
                                onclick: move |e| e.stop_propagation(),
                                onchange: move |e| {
                                    e.stop_propagation();
                                    let value = e.value();
                                    edit_group.set(if value.is_empty() {
                                        None
                                    } else {
                                        value.parse::<i64>().ok().map(|id| MessageId(FastHash(id)))
                                    });
                                },
                                option { value: "", "Ungrouped" }
                                for (group_id, group_name) in groups.iter() {
                                    option { value: "{group_id.0 .0}", "{group_name}" }
                                }
                            }
                        }
                    }

                    // Save/Cancel buttons
                    div { class: "flex gap-2",
                        button {
                            r#type: "button",
                            class: "px-3 py-1 text-sm bg-accent hover:bg-accent/80 text-white rounded transition-colors",
                            onclick: {
                                let msg_id = msg_id.clone();
                                move |e| {
                                    e.stop_propagation();

                                    // Validate icon
                                    let icon_val = edit_icon.read().trim().to_string();
                                    if !icon_val.is_empty() {
                                        if let Err(err) = validate_icon(&icon_val) {
                                            error_msg.set(Some(err));
                                            return;
                                        }
                                    }

                                    // Validate name
                                    let name_val = edit_name.read().trim().to_string();
                                    if name_val.is_empty() {
                                        error_msg.set(Some("Name cannot be empty".to_string()));
                                        return;
                                    }

                                    error_msg.set(None);

                                    if let Some(ref handler) = on_edit {
                                        let desc = edit_description.read().trim().to_string();
                                        let current_parent = current_parent_for_save.clone();
                                        let selected_group = (*edit_group.read()).clone();
                                        let new_parent = if allow_group_change
                                            && selected_group != current_parent
                                        {
                                            Some(selected_group)
                                        } else {
                                            None
                                        };
                                        handler.call(CategoryEditData {
                                            message_id: msg_id.clone(),
                                            new_name: name_val,
                                            new_description: if desc.is_empty() { None } else { Some(desc) },
                                            new_icon: if icon_val.is_empty() { None } else { Some(icon_val) },
                                            new_color: edit_color.read().clone(),
                                            new_parent,
                                        });
                                    }
                                    is_editing.set(false);
                                }
                            },
                            "Save"
                        }
                        button {
                            r#type: "button",
                            class: "px-3 py-1 text-sm bg-surface hover:bg-surface-hover text-text rounded transition-colors",
                            onclick: move |e| {
                                e.stop_propagation();
                                error_msg.set(None);
                                is_editing.set(false);
                            },
                            "Cancel"
                        }
                    }
                }
            }

            // Child boards inside the section card (home page)
            if !category.is_group && !child_boards.is_empty() {
                div { class: "px-4 pb-2 flex flex-wrap items-center gap-2 text-xs text-text-muted",
                    span { "Child Boards:" }
                    for (child_id, child_name) in child_boards.iter() {
                        if let Some(handler) = on_child_click.as_ref() {
                            button {
                                key: "{child_id:?}",
                                r#type: "button",
                                class: "hover:text-accent transition-colors",
                                onclick: {
                                    let handler = handler.clone();
                                    let child_id = child_id.clone();
                                    move |evt| {
                                        evt.stop_propagation();
                                        handler.call(child_id.clone());
                                    }
                                },
                                "{child_name}"
                            }
                        }
                    }
                }
            }

            // Action buttons overlay (on hover)
            if has_actions && *is_hovered.read() && !*is_editing.read() {
                div {
                    class: "absolute right-3 top-1/2 -translate-y-1/2 flex gap-1 bg-panel rounded shadow border border-border px-1 py-0.5",
                    onclick: move |e| e.stop_propagation(),

                    if on_edit.is_some() {
                        button {
                            r#type: "button",
                            class: "text-xs text-text-muted hover:text-text px-1",
                            onclick: {
                                let name = name.to_string();
                                let desc = description.map(|s| s.to_string()).unwrap_or_default();
                                let ic = icon.to_string();
                                let col = color.to_string();
                                move |_| {
                                    edit_name.set(name.clone());
                                    edit_description.set(desc.clone());
                                    edit_icon.set(ic.clone());
                                    edit_color.set(col.clone());
                                    edit_group.set(category.parent_category_id.clone());
                                    error_msg.set(None);
                                    is_editing.set(true);
                                }
                            },
                            "edit"
                        }
                    }
                    if let Some(ref delete_handler) = on_request_delete {
                        button {
                            r#type: "button",
                            class: "text-xs text-text-muted hover:text-red-500 px-1",
                            onclick: {
                                let handler = delete_handler.clone();
                                let msg_id = msg_id.clone();
                                move |_| handler.call(msg_id.clone())
                            },
                            "delete"
                        }
                    }
                }
            }
        }
    }
}
