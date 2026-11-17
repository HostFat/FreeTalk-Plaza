use dioxus::prelude::*;
use dioxus_free_icons::icons::fa_solid_icons::{FaPen, FaXmark};
use dioxus_free_icons::Icon;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use super::emoji_picker::EmojiPicker;
use super::ReplyContext;
use crate::components::app::{BOARDS, CURRENT_BOARD, CURRENT_CATEGORY};
use crate::board_data::{PendingSend, PendingUpload};
use crate::util::image_processing::{prepare_image, ImageMode};
use plaza_core::board_state::images::ImageRef;
use plaza_core::board_state::message::MessageId;

#[derive(Clone, Debug, PartialEq)]
enum AttachmentState {
    Uploading,
    Ready(ImageRef),
    Failed(String),
}

#[derive(Clone, Debug, PartialEq)]
struct Attachment {
    id: String,
    name: String,
    alt: String,
    nsfw: bool,
    state: AttachmentState,
}

/// Upload one prepared record, then drop it from the durable queue.
async fn upload_record(
    record: PendingUpload,
    mut attachments: Signal<Vec<Attachment>>,
    id: String,
) {
    let Some(board_key) = CURRENT_BOARD.read().owner_key else {
        return;
    };
    let Some(board_data) = BOARDS.read().map.get(&board_key).cloned() else {
        return;
    };
    let result = crate::util::uploads::upload_pending(&board_data, &record).await;

    attachments.with_mut(|list| {
        if let Some(slot) = list.iter_mut().find(|attachment| attachment.id == id) {
            slot.state = match &result {
                Ok(image) => AttachmentState::Ready(image.clone()),
                Err(error) => AttachmentState::Failed(error.clone()),
            };
        }
    });
    if let Ok(image) = &result {
        // Keep the queued record with its blob until the post is published:
        // a reload that lands between the upload and the publish still has the
        // reference. The send path removes it.
        crate::util::pending_uploads::set_image(&id, image);
        crate::util::pending_send::image_uploaded(board_key, &id, image);
    }
}

/// Start the upload of the chosen files, one attachment row each. The prepared
/// bytes are written to the delegate queue first so a reload keeps them.
fn add_attachment_files(
    files: Vec<web_sys::File>,
    mut attachments: Signal<Vec<Attachment>>,
    mut next_id: Signal<u64>,
    mode: ImageMode,
    reply_target: Option<MessageId>,
) {
    let Some(board_key) = CURRENT_BOARD.read().owner_key else {
        return;
    };
    let Some(board_data) = BOARDS.read().map.get(&board_key).cloned() else {
        return;
    };
    let max_images = board_data
        .board_state
        .configuration
        .configuration
        .images_per_message() as usize;
    // A restricted section seals its images, and so does a private board.
    let section = CURRENT_CATEGORY.read().category_id.clone();
    let secret = board_data.image_upload_secret(section.as_ref(), reply_target.as_ref());
    let now = crate::util::get_current_system_time()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);

    for file in files {
        if attachments.read().len() >= max_images {
            break;
        }
        let counter = *next_id.peek();
        let id = format!("{now}-{counter}");
        next_id.set(counter + 1);
        let name = file.name();
        attachments.with_mut(|list| {
            list.push(Attachment {
                id: id.clone(),
                name: name.clone(),
                alt: name.clone(),
                nsfw: false,
                state: AttachmentState::Uploading,
            })
        });
        let id = id.clone();
        let name = name.clone();
        let mut attachments = attachments;
        spawn_local(async move {
            match prepare_image(&file, mode).await {
                Ok(prepared) => {
                    let record = PendingUpload {
                        id: id.clone(),
                        name: name.clone(),
                        alt: name.clone(),
                        nsfw: false,
                        mime: prepared.mime,
                        width: prepared.width,
                        height: prepared.height,
                        animated: prepared.animated,
                        bytes: prepared.bytes,
                        secret,
                        image: None,
                    };
                    crate::util::pending_uploads::queue(record.clone()).await;
                    upload_record(record, attachments, id).await;
                }
                Err(error) => {
                    attachments.with_mut(|list| {
                        if let Some(slot) = list.iter_mut().find(|attachment| attachment.id == id)
                        {
                            slot.state = AttachmentState::Failed(error);
                        }
                    });
                }
            }
        });
    }
}

/// Re-add the uploads left over from a previous session and retry them.
fn restore_pending_uploads(mut attachments: Signal<Vec<Attachment>>) {
    let Some(board_key) = CURRENT_BOARD.read().owner_key else {
        return;
    };
    let max_images = BOARDS
        .read()
        .map
        .get(&board_key)
        .map(|board| {
            board
                .board_state
                .configuration
                .configuration
                .images_per_message() as usize
        })
        .unwrap_or(4);
    spawn_local(async move {
        let records = crate::util::pending_uploads::list();
        for record in records {
            if attachments.read().len() >= max_images {
                break;
            }
            if attachments
                .read()
                .iter()
                .any(|attachment| attachment.id == record.id)
            {
                continue;
            }
            let id = record.id.clone();
            let name = record.name.clone();
            let alt = record.alt.clone();
            let nsfw = record.nsfw;
            let ready = record.image.clone();
            attachments.with_mut(|list| {
                list.push(Attachment {
                    id: id.clone(),
                    name,
                    alt,
                    nsfw,
                    state: match ready {
                        Some(image) => AttachmentState::Ready(image),
                        None => AttachmentState::Uploading,
                    },
                })
            });
            if record.image.is_none() {
                upload_record(record, attachments, id).await;
            }
        }
    });
}

/// Open the hidden file picker. Must run from a user gesture.
fn open_image_picker() {
    if let Some(document) = web_sys::window().and_then(|window| window.document()) {
        if let Some(element) = document.get_element_by_id("image-file-input") {
            if let Ok(input) = element.dyn_into::<web_sys::HtmlInputElement>() {
                input.click();
            }
        }
    }
}

/// Files chosen in the hidden input, clearing it so the same file can be
/// picked again.
fn selected_files() -> Option<Vec<web_sys::File>> {
    let document = web_sys::window()?.document()?;
    let input = document
        .get_element_by_id("image-file-input")?
        .dyn_into::<web_sys::HtmlInputElement>()
        .ok()?;
    let files = input.files()?;
    let list: Vec<web_sys::File> = (0..files.length())
        .filter_map(|index| files.get(index))
        .collect();
    input.set_value("");
    Some(list)
}

/// Post input component with a compose button that opens a modal.
/// The modal contains fields for title and content.
#[component]
pub fn PostInput(
    handle_send_message: EventHandler<(
        String,
        String,
        Option<ReplyContext>,
        Option<crate::util::messaging::PollDraft>,
        Vec<ImageRef>,
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
    let mut attachments = use_signal(Vec::<Attachment>::new);
    let mut next_attachment_id = use_signal(|| 1u64);
    let mut auto_send = use_signal(|| false);
    let mut image_mode = use_signal(|| ImageMode::StripMetadata);

    // Image permission: owner, admins and roles with can_attach_images may
    // attach, and the section rule always wins over the role.
    let can_write = use_memo(move || {
        let Some(key) = CURRENT_BOARD.read().owner_key else {
            return false;
        };
        BOARDS
            .read()
            .map
            .get(&key)
            .map(|board| board.may_write_content())
            .unwrap_or(false)
    });
    let may_attach_images = use_memo(move || {
        let Some(key) = CURRENT_BOARD.read().owner_key else {
            return false;
        };
        let section = CURRENT_CATEGORY.read().category_id.clone();
        BOARDS
            .read()
            .map
            .get(&key)
            .map(|board| board.may_attach_images(section.as_ref()))
            .unwrap_or(false)
    });

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
            restore_pending_uploads(attachments);
            show_modal.set(true);
        }
    };

    let mut send_message = move || {
        // An image still uploading: queue the send, the effect below fires it
        // once every blob is ready. The message never points at a missing blob.
        if attachments
            .read()
            .iter()
            .any(|attachment| matches!(attachment.state, AttachmentState::Uploading))
        {
            // Persist the intent so a reload finishes the upload and sends it.
            // A poll keeps its in-memory behaviour: polls carry no images.
            if !*poll_enabled.peek() {
                if let Some(board_key) = CURRENT_BOARD.read().owner_key {
                    let reply = replying_to.peek().clone();
                    let mut images = Vec::new();
                    let mut attachment_ids = Vec::new();
                    for attachment in attachments.read().iter() {
                        match &attachment.state {
                            AttachmentState::Ready(image) => {
                                let mut image = image.clone();
                                image.alt = if attachment.alt.trim().is_empty() {
                                    attachment.name.clone()
                                } else {
                                    attachment.alt.trim().to_string()
                                };
                                image.nsfw = attachment.nsfw;
                                images.push(image);
                            }
                            AttachmentState::Uploading => {
                                attachment_ids.push(attachment.id.clone());
                            }
                            AttachmentState::Failed(_) => {}
                        }
                    }
                    let draft = PendingSend {
                        title: title_text.peek().to_string(),
                        text: message_text.peek().to_string(),
                        reply_to: reply.as_ref().map(|reply| reply.message_id.clone()),
                        reply_author: reply.as_ref().map(|reply| reply.author_name.clone()),
                        reply_preview: reply
                            .as_ref()
                            .map(|reply| reply.content_preview.clone()),
                        category_id: CURRENT_CATEGORY.read().category_id.clone(),
                        attachment_ids,
                        images,
                        queued_at: chrono::Utc::now().timestamp_millis(),
                    };
                    crate::util::pending_send::queue(board_key, draft);
                }
            }
            auto_send.set(true);
            return;
        }

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
            let images: Vec<ImageRef> = attachments
                .read()
                .iter()
                .filter_map(|attachment| match &attachment.state {
                    AttachmentState::Ready(image) => {
                        let mut image = image.clone();
                        image.alt = if attachment.alt.trim().is_empty() {
                            attachment.name.clone()
                        } else {
                            attachment.alt.trim().to_string()
                        };
                        image.nsfw = attachment.nsfw;
                        Some(image)
                    }
                    _ => None,
                })
                .collect();

            title_text.set(String::new());
            message_text.set(String::new());
            replying_to.set(None);
            show_modal.set(false);
            poll_enabled.set(false);
            poll_options.set(vec![String::new(), String::new()]);
            poll_days.set(String::new());
            poll_multiselect.set(false);
            poll_error.set(None);
            let published_ids: Vec<String> = attachments
                .read()
                .iter()
                .map(|attachment| attachment.id.clone())
                .collect();
            attachments.set(Vec::new());
            crate::util::pending_uploads::remove_many(&published_ids);
            if let Some(board_key) = CURRENT_BOARD.read().owner_key {
                crate::util::pending_send::clear(board_key);
            }
            crate::util::drafts::clear();
            crate::util::drafts::persist();
            handle_send_message.call((title, content, reply_ctx, poll, images));
        }
    };

    // Publish automatically when the queued send finds every upload complete.
    let send_after_upload = send_message;
    use_effect(move || {
        let wanted = auto_send();
        let uploading = attachments
            .read()
            .iter()
            .any(|attachment| matches!(attachment.state, AttachmentState::Uploading));
        if wanted && !uploading && show_modal() {
            auto_send.set(false);
            let mut send = send_after_upload;
            send();
        }
    });

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

                    // Images: uploaded to their own contracts before sending.
                    if *may_attach_images.read() {
                    div { class: "px-6 py-3 border-t border-border space-y-2",
                        div { class: "flex items-center justify-between",
                            span { class: "text-sm font-medium text-text", "Images" }
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 bg-surface hover:bg-surface-hover border border-border rounded-lg text-xs text-text transition-colors",
                                onclick: move |_| open_image_picker(),
                                "Attach image"
                            }
                        }
                        input {
                            id: "image-file-input",
                            r#type: "file",
                            accept: "image/png,image/jpeg,image/webp,image/gif",
                            multiple: true,
                            class: "hidden",
                            onchange: move |_| {
                                if let Some(files) = selected_files() {
                                    let reply_target = replying_to
                                        .read()
                                        .as_ref()
                                        .map(|reply| reply.message_id.clone());
                                    add_attachment_files(
                                        files,
                                        attachments,
                                        next_attachment_id,
                                        *image_mode.peek(),
                                        reply_target,
                                    );
                                }
                            },
                        }
                        div { class: "flex items-center gap-2",
                            label { class: "text-xs text-text-muted", "Format" }
                            select {
                                class: "px-2 py-1 bg-background border border-border rounded text-xs text-text",
                                value: "{image_mode.read().label()}",
                                onchange: move |event| {
                                    let value = event.value();
                                    let chosen = [
                                        ImageMode::StripMetadata,
                                        ImageMode::Webp2048,
                                        ImageMode::Webp1280,
                                        ImageMode::KeepOriginal,
                                    ]
                                    .into_iter()
                                    .find(|candidate| candidate.label() == value)
                                    .unwrap_or(ImageMode::StripMetadata);
                                    image_mode.set(chosen);
                                },
                                for candidate in [
                                    ImageMode::StripMetadata,
                                    ImageMode::Webp2048,
                                    ImageMode::Webp1280,
                                    ImageMode::KeepOriginal,
                                ] {
                                    option { value: "{candidate.label()}", "{candidate.label()}" }
                                }
                            }
                        }
                        if attachments.read().is_empty() {
                            p { class: "text-xs text-text-muted",
                                "Up to 4 images. The default removes EXIF and the other metadata without re-encoding; GIFs keep their animation."
                            }
                        }
                        for attachment in attachments.read().clone() {
                            div { key: "{attachment.id}", class: "bg-surface rounded-lg p-2 space-y-1 text-xs",
                                div { class: "flex items-center justify-between gap-2",
                                    span { class: "text-text truncate", "{attachment.name}" }
                                    {match &attachment.state {
                                        AttachmentState::Uploading => rsx! {
                                            span { class: "text-text-muted flex items-center gap-2",
                                                div { class: "animate-spin w-3 h-3 border-2 border-text-muted border-t-transparent rounded-full" }
                                                "Uploading..."
                                            }
                                        },
                                        AttachmentState::Ready(image) => rsx! {
                                            span { class: "text-text-muted",
                                                "{image.width}x{image.height} · {image.bytes / 1024} KB"
                                            }
                                        },
                                        AttachmentState::Failed(error) => rsx! {
                                            span { class: "text-red-400 truncate", "{error}" }
                                            button {
                                                r#type: "button",
                                                class: "text-xs text-accent hover:underline",
                                                onclick: {
                                                    let id = attachment.id.clone();
                                                    move |_| {
                                                        let Some(record) = crate::util::pending_uploads::list()
                                                            .into_iter()
                                                            .find(|record| record.id == id)
                                                        else {
                                                            return;
                                                        };
                                                        attachments.with_mut(|list| {
                                                            if let Some(slot) = list.iter_mut().find(|entry| entry.id == id) {
                                                                slot.state = AttachmentState::Uploading;
                                                            }
                                                        });
                                                        let id = id.clone();
                                                        spawn_local(async move {
                                                            upload_record(record, attachments, id).await;
                                                        });
                                                    }
                                                },
                                                "Retry"
                                            }
                                        },
                                    }}
                                    button {
                                        r#type: "button",
                                        class: "text-text-muted hover:text-red-400",
                                        title: "Remove",
                                        onclick: {
                                            let id = attachment.id.clone();
                                            move |_| {
                                                // Dismissing the row also drops the queued
                                                // upload, otherwise it comes back on reload.
                                                crate::util::pending_uploads::remove(&id);
                                                attachments.with_mut(|list| list.retain(|entry| entry.id != id));
                                            }
                                        },
                                        "✕"
                                    }
                                }
                                input {
                                    r#type: "text",
                                    class: "w-full px-2 py-1 bg-background border border-border rounded text-text placeholder-text-muted",
                                    placeholder: "Describe the image (required)",
                                    value: "{attachment.alt}",
                                    oninput: {
                                        let id = attachment.id.clone();
                                        move |event| {
                                            let value = event.value();
                                            attachments.with_mut(|list| {
                                                if let Some(entry) = list.iter_mut().find(|entry| entry.id == id) {
                                                    entry.alt = value;
                                                }
                                            });
                                        }
                                    },
                                }
                                label { class: "flex items-center gap-2 text-text-muted",
                                    input {
                                        r#type: "checkbox",
                                        checked: attachment.nsfw,
                                        onchange: {
                                            let id = attachment.id.clone();
                                            move |event| {
                                                let checked = event.checked();
                                                attachments.with_mut(|list| {
                                                    if let Some(entry) = list.iter_mut().find(|entry| entry.id == id) {
                                                        entry.nsfw = checked;
                                                    }
                                                });
                                            }
                                        },
                                    }
                                    "NSFW (labelled and hidden behind a click)"
                                }
                            }
                        }
                        if auto_send() {
                            p { class: "text-xs text-accent", "Uploading, the post will be published automatically." }
                        }
                    }
                    } else if *can_write.read() {
                        p { class: "px-6 py-3 border-t border-border text-xs text-text-muted",
                            "Images are disabled in this section or for your role."
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
