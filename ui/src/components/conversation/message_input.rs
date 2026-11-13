use dioxus::prelude::*;
use dioxus_free_icons::icons::fa_solid_icons::{FaPen, FaXmark};
use dioxus_free_icons::Icon;

use super::emoji_picker::EmojiPicker;
use super::ReplyContext;

/// Post input component with a compose button that opens a modal.
/// The modal contains fields for title and content.
#[component]
pub fn PostInput(
    handle_send_message: EventHandler<(
        String,
        String,
        Option<ReplyContext>,
        Option<crate::util::messaging::PollDraft>,
    )>,
    replying_to: Signal<Option<ReplyContext>>,
    on_request_edit_last: EventHandler<()>,
    /// Default reply context - applied when modal opens if replying_to is None
    #[props(default)]
    default_reply_to: Option<ReplyContext>,
    /// Inside a category: the button starts a new topic, not a reply.
    #[props(default)]
    in_category: bool,
    /// Inside a single post: the button starts a reply to that post.
    #[props(default)]
    in_post: bool,
    /// Only render the modal; the page provides its own compose button.
    #[props(default)]
    hide_button: bool,
    /// Maximum title length (from board configuration)
    max_title_size: usize,
    /// Maximum message length (from board configuration)
    max_message_size: usize,
) -> Element {
    let mut show_modal = use_signal(|| false);
    let mut title_text = use_signal(String::new);
    let mut message_text = use_signal(String::new);
    let mut show_emoji_picker = use_signal(|| false);
    let mut show_preview = use_signal(|| false);
    let mut draft_restored = use_signal(|| false);
    let mut save_generation = use_signal(|| 0u64);
    let mut poll_enabled = use_signal(|| false);
    let mut poll_options = use_signal(|| vec![String::new(), String::new()]);
    let mut poll_multiselect = use_signal(|| false);
    let mut poll_days = use_signal(String::new);
    let mut poll_error = use_signal(|| None::<String>);

    // Keep the draft in BoardData and write the delegate store. The compose
    // path uses this directly; typing waits for a pause so every keystroke
    // does not rewrite the board state.
    let save_draft_now = move || {
        if crate::util::drafts::store(
            &title_text.peek(),
            &message_text.peek(),
            replying_to.peek().as_ref(),
        ) {
            crate::util::drafts::persist();
        }
    };
    let mut schedule_save = move || {
        let generation = *save_generation.peek() + 1;
        save_generation.set(generation);
        spawn(async move {
            futures_timer::Delay::new(std::time::Duration::from_millis(800)).await;
            if *save_generation.peek() == generation {
                if crate::util::drafts::store(
                    &title_text.peek(),
                    &message_text.peek(),
                    replying_to.peek().as_ref(),
                ) {
                    crate::util::drafts::persist();
                }
            }
        });
    };

    // Open modal when replying_to changes to Some (from clicking reply button)
    use_effect(move || {
        if replying_to.read().is_some() && !show_modal() {
            show_modal.set(true);
        }
    });

    // Restore the saved draft when the user opens the composer for a new post.
    // A draft never overrides text the composer already has, such as a quote,
    // and never overrides a reply the user started from the post list.
    let mut restore_draft = move || {
        if *draft_restored.peek() {
            return;
        }
        draft_restored.set(true);
        if !title_text.peek().is_empty() || !message_text.peek().is_empty() {
            return;
        }
        let Some(draft) = crate::util::drafts::load() else {
            return;
        };
        title_text.set(draft.title);
        message_text.set(draft.text);
        if let Some(target) = draft.reply_to {
            replying_to.set(Some(crate::util::messaging::ReplyContext {
                message_id: target,
                author_name: draft.reply_author,
                content_preview: draft.reply_preview,
            }));
        }
    };

    // Other pages can ask the shared composer to open, for example the
    // "New post" button inside a category. Quotes collected from the post
    // list are inserted in one block and reply to the last quoted post.
    let default_reply_for_request = default_reply_to.clone();
    let mut last_compose_request = use_signal(|| *crate::components::app::COMPOSE_REQUEST.read());
    use_effect(move || {
        let request = *crate::components::app::COMPOSE_REQUEST.read();
        if request == *last_compose_request.read() {
            return;
        }
        last_compose_request.set(request);

        let quotes = crate::components::app::QUOTE_COLLECTION.read().clone();
        if !quotes.is_empty() {
            let mut text = String::new();
            for quote in quotes.iter() {
                text.push_str(&format!("> {}: {}\n\n", quote.author, quote.text));
            }
            let existing = message_text.peek().clone();
            message_text.set(format!("{text}{existing}"));
            if let Some(last) = quotes.last() {
                replying_to.set(Some(crate::util::messaging::ReplyContext {
                    message_id: last.target,
                    author_name: last.author.clone(),
                    content_preview: last.preview.clone(),
                }));
            }
            crate::components::app::QUOTE_COLLECTION.with_mut(|quotes| quotes.clear());
        }

        if replying_to.peek().is_none() {
            if let Some(default) = default_reply_for_request.clone() {
                replying_to.set(Some(default));
            }
        }
        restore_draft();
        show_modal.set(true);
        save_draft_now();
    });

    let has_draft = use_memo(move || crate::util::drafts::load().is_some());

    // Handler for opening the modal via Compose button
    let open_modal = {
        let default_reply = default_reply_to.clone();
        move |_| {
            // If no explicit reply is set but we have a default, use it
            if replying_to.peek().is_none() {
                if let Some(ref default) = default_reply {
                    replying_to.set(Some(default.clone()));
                }
            }
            restore_draft();
            show_modal.set(true);
        }
    };

    let mut send_message = move || {
        let title = title_text.peek().to_string();
        let content = message_text.peek().to_string();
        let reply_ctx = replying_to.peek().clone();
        let wants_poll = *poll_enabled.peek() && reply_ctx.is_none();

        let poll = if wants_poll {
            let options: Vec<String> = poll_options
                .peek()
                .iter()
                .map(|option| option.trim().to_string())
                .filter(|option| !option.is_empty())
                .collect();
            let days = poll_days.peek().trim().parse::<i64>().unwrap_or(0);
            let closes_at = if days > 0 {
                Some(chrono::Utc::now().timestamp_millis() + days * 24 * 60 * 60 * 1000)
            } else {
                None
            };
            let draft = crate::util::messaging::PollDraft {
                options,
                closes_at,
                multiselect: *poll_multiselect.peek(),
            };
            let poll_content = plaza_core::board_state::content::PollContentV1::new(
                title.clone(),
                content.clone(),
                draft.options.clone(),
                draft.closes_at,
                draft.multiselect,
            );
            if let Err(error) = poll_content.validate() {
                poll_error.set(Some(error));
                return;
            }
            poll_error.set(None);
            Some(draft)
        } else {
            None
        };

        if !content.is_empty() || poll.is_some() {
            title_text.set(String::new());
            message_text.set(String::new());
            replying_to.set(None);
            show_modal.set(false);
            poll_enabled.set(false);
            poll_options.set(vec![String::new(), String::new()]);
            poll_days.set(String::new());
            poll_multiselect.set(false);
            poll_error.set(None);
            crate::util::drafts::clear();
            crate::util::drafts::persist();
            handle_send_message.call((title, content, reply_ctx, poll));
        }
    };

    // Handle emoji selection - insert at end of message
    let handle_emoji_select = move |emoji: String| {
        let current = message_text.peek().to_string();
        message_text.set(format!("{}{}", current, emoji));
        schedule_save();
    };

    rsx! {
        // A category starts a new topic; a post starts a reply. The reply
        // section keeps its own caption.
        if !hide_button {
        if in_category {
            button {
                class: "flex items-center gap-2 px-4 py-2.5 bg-accent hover:bg-accent-hover text-white font-medium rounded-xl transition-colors",
                onclick: open_modal,
                title: if has_draft() { "Compose Topic (draft saved)" } else { "Compose Topic" },
                Icon { icon: FaPen, width: 14, height: 14 }
                "Compose Topic"
            }
        } else if default_reply_to.is_some() && !in_post {
            button {
                class: "flex items-center gap-2 px-4 py-2.5 bg-accent hover:bg-accent-hover text-white font-medium rounded-xl transition-colors",
                onclick: open_modal,
                Icon { icon: FaPen, width: 14, height: 14 }
                "Compose Reply"
            }
        } else {
            button {
                class: "relative p-3 bg-accent hover:bg-accent-hover text-white rounded-xl transition-colors",
                onclick: open_modal,
                title: if in_post {
                    if has_draft() { "Compose Reply (draft saved)" } else { "Compose Reply" }
                } else if has_draft() {
                    "Compose Topic (draft saved)"
                } else {
                    "Compose Topic"
                },
                Icon { icon: FaPen, width: 18, height: 18 }
                if has_draft() {
                    span { class: "absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-white border border-accent" }
                }
            }
        }
        }

        // Compose modal
        if show_modal() {
            div {
                class: "fixed inset-0 bg-black/50 flex items-center justify-center z-50",
                onclick: move |_| {
                    save_draft_now();
                    show_modal.set(false);
                    replying_to.set(None);
                },
                div {
                    class: "bg-panel rounded-xl shadow-xl w-full max-w-2xl mx-4 max-h-[90vh] flex flex-col",
                    onclick: move |e| e.stop_propagation(),

                    // Modal header
                    div { class: "flex items-center justify-between px-6 py-4 border-b border-border",
                        h2 { class: "text-lg font-semibold text-text",
                            if replying_to.read().is_some() { "Reply to Topic" } else { "New Topic" }
                        }
                        button {
                            class: "p-2 rounded-lg text-text-muted hover:text-text hover:bg-surface transition-colors",
                            onclick: move |_| {
                                save_draft_now();
                                show_modal.set(false);
                                replying_to.set(None);
                            },
                            Icon { icon: FaXmark, width: 16, height: 16 }
                        }
                    }

                    // Modal body
                    div { class: "flex-1 overflow-y-auto px-6 py-4 space-y-4",
                        // Reply preview strip
                        {
                            let reply = replying_to.read();
                            if let Some(ctx) = reply.as_ref() {
                                let author = ctx.author_name.clone();
                                let preview = ctx.content_preview.clone();
                                rsx! {
                                    div { class: "flex items-center gap-2 px-3 py-2 bg-surface border-l-2 border-accent rounded text-sm text-text-muted",
                                        span { class: "flex-1 truncate",
                                            span { class: "font-medium", "\u{21a9} Replying to @{author}: " }
                                            "{preview}"
                                        }
                                        button {
                                            class: "text-text-muted hover:text-text transition-colors flex-shrink-0",
                                            title: "Cancel reply",
                                            onclick: move |_| replying_to.set(None),
                                            "\u{00d7}"
                                        }
                                    }
                                }
                            } else {
                                rsx! {}
                            }
                        }

                        // Title field
                        div { class: "space-y-1.5",
                            div { class: "flex items-center justify-between",
                                label { class: "block text-sm font-medium text-text",
                                    "Title"
                                    span { class: "text-text-muted font-normal", " (optional)" }
                                }
                                span {
                                    class: if title_text.read().len() > max_title_size { "text-xs text-red-400" } else { "text-xs text-text-muted" },
                                    "{title_text.read().len()}/{max_title_size}"
                                }
                            }
                            input {
                                r#type: "text",
                                class: "w-full px-4 py-2.5 bg-surface border border-border rounded-lg text-text placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent transition-colors",
                                placeholder: "Add a title...",
                                maxlength: max_title_size as i64,
                                value: "{title_text}",
                                oninput: move |evt| {
                                    // Strip newlines from title
                                    let value = evt.value().replace(['\n', '\r'], "");
                                    title_text.set(value);
                                    schedule_save();
                                },
                            }
                        }

                        // Content field
                        div { class: "space-y-1.5",
                            div { class: "flex items-center justify-between",
                                label { class: "block text-sm font-medium text-text",
                                    if replying_to.read().is_some() { "Reply" } else { "Topic" }
                                }
                                span {
                                    class: if message_text.read().len() > max_message_size { "text-xs text-red-400" } else { "text-xs text-text-muted" },
                                    "{message_text.read().len()}/{max_message_size}"
                                }
                            }
                            // Markdown toolbar
                            div { class: "flex flex-wrap items-center gap-1 mb-2",
                                button {
                                    r#type: "button",
                                    class: "px-2 py-1 text-xs font-bold bg-surface hover:bg-surface-hover rounded",
                                    title: "Bold",
                                    onclick: move |_| {
                                        let v = crate::util::markdown_wrap("message-input", "**", "**");
                                        if !v.is_empty() { message_text.set(v); }
                                    },
                                    "B"
                                }
                                button {
                                    r#type: "button",
                                    class: "px-2 py-1 text-xs italic bg-surface hover:bg-surface-hover rounded",
                                    title: "Italic",
                                    onclick: move |_| {
                                        let v = crate::util::markdown_wrap("message-input", "*", "*");
                                        if !v.is_empty() { message_text.set(v); }
                                    },
                                    "I"
                                }
                                button {
                                    r#type: "button",
                                    class: "px-2 py-1 text-xs bg-surface hover:bg-surface-hover rounded font-mono",
                                    title: "Inline code",
                                    onclick: move |_| {
                                        let v = crate::util::markdown_wrap("message-input", "`", "`");
                                        if !v.is_empty() { message_text.set(v); }
                                    },
                                    "</>"
                                }
                                button {
                                    r#type: "button",
                                    class: "px-2 py-1 text-xs bg-surface hover:bg-surface-hover rounded",
                                    title: "Link",
                                    onclick: move |_| {
                                        let v = crate::util::markdown_wrap("message-input", "[", "](https://)");
                                        if !v.is_empty() { message_text.set(v); }
                                    },
                                    "Link"
                                }
                                button {
                                    r#type: "button",
                                    class: "px-2 py-1 text-xs bg-surface hover:bg-surface-hover rounded",
                                    title: "Quote",
                                    onclick: move |_| {
                                        let v = crate::util::markdown_wrap("message-input", "> ", "");
                                        if !v.is_empty() { message_text.set(v); }
                                    },
                                    "Quote"
                                }
                                button {
                                    r#type: "button",
                                    class: "px-2 py-1 text-xs bg-surface hover:bg-surface-hover rounded",
                                    title: "Bullet list",
                                    onclick: move |_| {
                                        let v = crate::util::markdown_wrap("message-input", "- ", "");
                                        if !v.is_empty() { message_text.set(v); }
                                    },
                                    "List"
                                }
                                button {
                                    r#type: "button",
                                    class: "px-2 py-1 text-xs bg-surface hover:bg-surface-hover rounded",
                                    title: "Heading",
                                    onclick: move |_| {
                                        let v = crate::util::markdown_wrap("message-input", "### ", "");
                                        if !v.is_empty() { message_text.set(v); }
                                    },
                                    "H"
                                }
                                span { class: "text-xs text-text-muted ml-1", "Markdown supported" }
                                button {
                                    r#type: "button",
                                    class: if *poll_enabled.read() {
                                        "px-2 py-1 text-xs rounded bg-accent text-white ml-2"
                                    } else {
                                        "px-2 py-1 text-xs bg-surface hover:bg-surface-hover rounded ml-2"
                                    },
                                    title: "Add a poll to this new topic",
                                    onclick: move |_| {
                                        let next = !*poll_enabled.read();
                                        poll_enabled.set(next);
                                        poll_error.set(None);
                                    },
                                    "Poll"
                                }
                                button {
                                    r#type: "button",
                                    class: "text-xs text-accent hover:text-accent/80 ml-2",
                                    onclick: move |_| {
                                        let next = !*show_preview.read();
                                        show_preview.set(next);
                                    },
                                    if *show_preview.read() { "Write" } else { "Preview" }
                                }
                            }
                            div { class: "relative",
                                // Emoji picker backdrop
                                if show_emoji_picker() {
                                    div {
                                        class: "fixed inset-0 z-40",
                                        onclick: move |_| show_emoji_picker.set(false),
                                    }
                                }
                                div { class: "flex gap-2",
                                    // Emoji picker button
                                    div { class: "relative self-start pt-2",
                                        button {
                                            class: "p-2 rounded-lg hover:bg-surface transition-colors",
                                            title: "Insert emoji",
                                            onclick: move |_| show_emoji_picker.set(!show_emoji_picker()),
                                            span {
                                                class: "text-lg",
                                                style: "filter: grayscale(100%); opacity: 0.6;",
                                                "🙂"
                                            }
                                        }
                                        if show_emoji_picker() {
                                            div {
                                                class: "absolute bottom-full left-0 mb-2 z-50",
                                                EmojiPicker {
                                                    on_select: handle_emoji_select,
                                                    on_close: move |_| show_emoji_picker.set(false),
                                                }
                                            }
                                        }
                                    }
                                    textarea {
                                        id: "message-input",
                                        class: "flex-1 px-4 py-2.5 bg-surface border border-border rounded-lg text-text placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent transition-colors resize-none min-h-[120px]",
                                        placeholder: "Type your message...",
                                        value: "{message_text}",
                                        rows: "5",
                                        oninput: move |evt| {
                                            message_text.set(evt.value().to_string());
                                            schedule_save();
                                        },
                                        onkeydown: move |evt| {
                                            // Ctrl/Cmd+Enter sends the message
                                            if evt.key() == Key::Enter && (evt.modifiers().ctrl() || evt.modifiers().meta()) {
                                                evt.prevent_default();
                                                send_message();
                                            }
                                            // Escape closes modal
                                            if evt.key() == Key::Escape {
                                                save_draft_now();
                                                show_modal.set(false);
                                                replying_to.set(None);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if poll_enabled() {
                        div { class: "px-6 pb-4 pt-1 space-y-2",
                            div { class: "flex items-center justify-between",
                                span { class: "text-sm font-medium text-text", "Poll options" }
                                span { class: "text-xs text-text-muted", "The title is the question" }
                            }
                            for (index, option) in poll_options.read().iter().enumerate() {
                                div { class: "flex items-center gap-2",
                                    input {
                                        r#type: "text",
                                        class: "flex-1 px-3 py-2 bg-surface border border-border rounded-lg text-text text-sm placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-accent/50",
                                        placeholder: "Option {index + 1}",
                                        value: "{option}",
                                        oninput: move |evt| {
                                            poll_options.with_mut(|options| {
                                                if let Some(slot) = options.get_mut(index) {
                                                    *slot = evt.value();
                                                }
                                            });
                                        },
                                    }
                                    if poll_options.read().len() > 2 {
                                        button {
                                            r#type: "button",
                                            class: "px-2 py-1 text-text-muted hover:text-text text-sm",
                                            title: "Remove option",
                                            onclick: move |_| {
                                                poll_options.with_mut(|options| {
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
                            div { class: "flex flex-wrap items-center gap-3 text-xs",
                                if poll_options.read().len() < plaza_core::board_state::content::MAX_POLL_OPTIONS {
                                    button {
                                        r#type: "button",
                                        class: "px-2 py-1 bg-surface hover:bg-surface-hover text-text rounded",
                                        onclick: move |_| {
                                            poll_options.with_mut(|options| options.push(String::new()));
                                        },
                                        "+ Option"
                                    }
                                }
                                button {
                                    r#type: "button",
                                    class: "px-2 py-1 bg-surface hover:bg-surface-hover text-text rounded",
                                    onclick: move |_| {
                                        let next = !*poll_multiselect.read();
                                        poll_multiselect.set(next);
                                    },
                                    if *poll_multiselect.read() { "Multiple answers" } else { "Single answer" }
                                }
                                label { class: "flex items-center gap-1 text-text-muted",
                                    "Closes in"
                                    input {
                                        r#type: "number",
                                        min: "0",
                                        max: "365",
                                        class: "w-16 px-2 py-1 bg-surface border border-border rounded text-text",
                                        value: "{poll_days}",
                                        oninput: move |evt| poll_days.set(evt.value()),
                                    }
                                    "days (0 = never)"
                                }
                            }
                            if let Some(error) = poll_error.read().as_ref() {
                                p { class: "text-xs text-red-400", "{error}" }
                            }
                        }
                    }

                    if *show_preview.read() {
                        div { class: "px-6 pb-4",
                            div {
                                class: "prose prose-base dark:prose-invert max-w-none p-4 bg-surface border border-border rounded-lg",
                                dangerous_inner_html: "{crate::util::markdown::text_to_html(&message_text.read())}",
                            }
                        }
                    }

                    // Modal footer - wrapped in form for iPad virtual keyboard support
                    form {
                        class: "flex items-center justify-between px-6 py-4 border-t border-border bg-surface/50",
                        onsubmit: move |evt| {
                            evt.prevent_default();
                            send_message();
                        },
                        span { class: "text-xs text-text-muted",
                            "Press Ctrl+Enter to send"
                        }
                        div { class: "flex gap-3",
                            button {
                                r#type: "button",
                                class: "px-4 py-2 rounded-lg bg-surface hover:bg-surface-hover text-text transition-colors",
                                onclick: move |_| {
                                    save_draft_now();
                                    show_modal.set(false);
                                    replying_to.set(None);
                                },
                                "Cancel"
                            }
                            button {
                                r#type: "submit",
                                class: "px-5 py-2 bg-accent hover:bg-accent-hover text-white font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed",
                                disabled: (message_text.read().is_empty() && !poll_enabled())
                                    || message_text.read().len() > max_message_size
                                    || title_text.read().len() > max_title_size
                                    || (poll_enabled() && title_text.read().trim().is_empty()),
                                if replying_to.read().is_some() { "Send Reply" } else { "Send Topic" }
                            }
                        }
                    }
                }
            }
        }
    }
}
