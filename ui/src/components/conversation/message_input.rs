use dioxus::prelude::*;
use dioxus_free_icons::icons::fa_solid_icons::{FaPen, FaXmark};
use dioxus_free_icons::Icon;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use super::emoji_picker::EmojiPicker;
use super::ReplyContext;
use crate::components::conversation::TopicThumb;
use crate::components::app::{BOARDS, CURRENT_BOARD, CURRENT_CATEGORY};
use crate::board_data::{PendingSend, PendingUpload};
use crate::util::image_processing::{prepare_image, ImageMode};
use plaza_core::board_state::images::{ImageAlign, ImagePlacement, ImageRef};
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
    if record.bytes.is_empty() {
        attachments.with_mut(|list| {
            if let Some(slot) = list.iter_mut().find(|attachment| attachment.id == id) {
                slot.state = AttachmentState::Failed("The image was not prepared".to_string());
            }
        });
        return;
    }
    let progress_id = id.clone();
    let progress = move |done: usize, total: usize| {
        crate::components::app::UPLOAD_PROGRESS
            .write()
            .insert(progress_id.clone(), (done, total));
    };
    let result =
        crate::util::uploads::upload_pending(&board_data, &record, Some(&progress)).await;

    attachments.with_mut(|list| {
        if let Some(slot) = list.iter_mut().find(|attachment| attachment.id == id) {
            slot.state = match &result {
                Ok((image, _)) => AttachmentState::Ready(image.clone()),
                Err(error) => AttachmentState::Failed(error.clone()),
            };
        }
    });
    if let Ok((image, copy)) = &result {
        // Keep the queued record with its blob until the post is published:
        // a reload that lands between the upload and the publish still has the
        // reference. The send path removes it.
        crate::util::pending_uploads::set_image(&id, image);
        crate::util::pending_send::image_uploaded(board_key, &id, image);
        if let Some(copy) = copy {
            crate::util::owned_images::record(image, copy.clone());
        }
    }
    crate::components::app::UPLOAD_PROGRESS.write().remove(&id);
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
        // Placeholder first: a Send during preparation must find a record.
        crate::util::pending_uploads::insert(PendingUpload {
            id: id.clone(),
            name: name.clone(),
            alt: name.clone(),
            nsfw: false,
            mime: "image/webp".to_string(),
            width: 0,
            height: 0,
            animated: false,
            bytes: Vec::new(),
            secret,
            image: None,
        });
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
                    crate::util::pending_uploads::update(&id, |stored| {
                        *stored = record.clone();
                    });
                    if let Err(error) = crate::util::pending_uploads::persist_now().await {
                        warn!("Could not persist the pending image: {error}");
                    }
                    upload_record(record, attachments, id).await;
                }
                Err(error) => {
                    crate::util::pending_uploads::remove(&id);
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
        crate::util::pending_uploads::ensure_loaded().await;
        let records = crate::util::pending_uploads::list();
        for record in records {
            if attachments.read().len() >= max_images {
                break;
            }
            if record.bytes.is_empty() {
                // A placeholder whose preparation never finished: nothing to
                // upload.
                dioxus::logger::tracing::warn!(
                    "Dropping empty pending upload {}",
                    record.id
                );
                crate::util::pending_uploads::remove(&record.id);
                continue;
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

fn file_from_bytes(name: &str, bytes: &[u8], mime: &str) -> Option<web_sys::File> {
    let array = js_sys::Uint8Array::from(bytes);
    let parts = js_sys::Array::new();
    parts.push(&array.buffer());
    let blob_options = web_sys::BlobPropertyBag::new();
    blob_options.set_type(mime);
    let blob =
        web_sys::Blob::new_with_buffer_source_sequence_and_options(&parts, &blob_options).ok()?;
    let blobs = js_sys::Array::new();
    blobs.push(&blob);
    let file_options = web_sys::FilePropertyBag::new();
    file_options.set_type(mime);
    web_sys::File::new_with_blob_sequence_and_options(&blobs.into(), name, &file_options).ok()
}

fn preview_url(bytes: &[u8], mime: &str) -> Option<String> {
    let array = js_sys::Uint8Array::from(bytes);
    let parts = js_sys::Array::new();
    parts.push(&array.buffer());
    let options = web_sys::BlobPropertyBag::new();
    options.set_type(mime);
    let blob =
        web_sys::Blob::new_with_buffer_source_sequence_and_options(&parts, &options).ok()?;
    web_sys::Url::create_object_url_with_blob(&blob).ok()
}

/// Bytes and metadata behind an attachment row: either a queued upload or a
/// previous upload reused from "Your images".
#[derive(Clone)]
struct EditSource {
    name: String,
    bytes: Vec<u8>,
    mime: String,
    width: u32,
    height: u32,
    retire: Option<[u8; 32]>,
}

fn attachment_source(id: &str, state: &AttachmentState) -> Option<EditSource> {
    if let Some(record) = crate::util::pending_uploads::list()
        .into_iter()
        .find(|record| record.id == id)
    {
        return Some(EditSource {
            name: record.name,
            bytes: record.bytes,
            mime: record.mime,
            width: record.width,
            height: record.height,
            retire: record.image.map(|image| image.instance),
        });
    }
    if let AttachmentState::Ready(image) = state {
        if let Some((bytes, mime)) =
            crate::util::owned_images::plaintext_for(&image.instance)
        {
            return Some(EditSource {
                name: image.alt.clone(),
                bytes,
                mime,
                width: image.width,
                height: image.height,
                retire: Some(image.instance),
            });
        }
    }
    None
}

/// Rotate or crop an attachment, then upload the edited image again.
fn edit_attachment(
    id: String,
    source: EditSource,
    edit: crate::util::image_processing::Transform,
    mut attachments: Signal<Vec<Attachment>>,
    next_id: Signal<u64>,
    reply_target: Option<MessageId>,
) {
    spawn_local(async move {
        match crate::util::image_processing::transform(&source.bytes, &source.mime, edit).await {
            Ok(prepared) => {
                let Some(file) = file_from_bytes(&source.name, &prepared.bytes, &prepared.mime)
                else {
                    return;
                };
                if let Some(old) = source.retire {
                    spawn_local(async move {
                        if let Err(error) =
                            crate::util::images::retire_in_contract(old).await
                        {
                            dioxus::logger::tracing::warn!(
                                "Could not retire the replaced image: {error}"
                            );
                        }
                    });
                }
                attachments.with_mut(|list| list.retain(|attachment| attachment.id != id));
                let _ = crate::util::pending_uploads::remove(&id);
                add_attachment_files(
                    vec![file],
                    attachments,
                    next_id,
                    ImageMode::KeepOriginal,
                    reply_target,
                );
            }
            Err(error) => {
                dioxus::logger::tracing::warn!("Could not edit the image: {error}");
            }
        }
    });
}

fn edit_attachment_from_row(
    id: String,
    state: AttachmentState,
    edit: crate::util::image_processing::Transform,
    attachments: Signal<Vec<Attachment>>,
    next_id: Signal<u64>,
    reply_target: Option<MessageId>,
    mut image_error: Signal<Option<String>>,
) {
    match attachment_source(&id, &state) {
        Some(source) => {
            image_error.set(None);
            edit_attachment(id, source, edit, attachments, next_id, reply_target);
        }
        None => image_error.set(Some(
            "The original bytes of this image are not on this device. Re-upload the file to edit it."
                .to_string(),
        )),
    }
}

/// Turn a browser file from a drag or paste event into a `File` the rest of
/// the pipeline already understands.
async fn file_from_data(data: &dioxus::html::FileData) -> Option<web_sys::File> {
    let bytes = data.read_bytes().await.ok()?;
    let mime = data.content_type().unwrap_or_default();
    let array = js_sys::Uint8Array::from(bytes.as_ref());
    let parts = js_sys::Array::new();
    parts.push(&array.buffer());
    let blob_options = web_sys::BlobPropertyBag::new();
    blob_options.set_type(&mime);
    let blob =
        web_sys::Blob::new_with_buffer_source_sequence_and_options(&parts, &blob_options).ok()?;
    let blobs = js_sys::Array::new();
    blobs.push(&blob);
    let file_options = web_sys::FilePropertyBag::new();
    file_options.set_type(&mime);
    web_sys::File::new_with_blob_sequence_and_options(&blobs.into(), &data.name(), &file_options)
        .ok()
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
    selected_files_from("image-file-input")
}

/// Same as [`selected_files`] for the visible developer input.
fn selected_files_from(input_id: &str) -> Option<Vec<web_sys::File>> {
    let document = web_sys::window()?.document()?;
    let input = document
        .get_element_by_id(input_id)?
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
    handle_send_message: Callback<
        (
            String,
            String,
            Option<ReplyContext>,
            Option<crate::util::messaging::PollDraft>,
            Vec<ImageRef>,
        ),
        Result<(), String>,
    >,
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
    let mut image_error = use_signal(|| None::<String>);
    let mut next_attachment_id = use_signal(|| 1u64);
    let mut auto_send = use_signal(|| false);
    let mut image_mode = use_signal(|| ImageMode::StripMetadata);
    // Graphical crop: preview URL and the selection in percent.
    let mut crop_target = use_signal(|| None::<String>);
    let mut crop_url = use_signal(|| None::<String>);
    let mut crop_x = use_signal(|| 0.0f64);
    let mut crop_y = use_signal(|| 0.0f64);
    let mut crop_w = use_signal(|| 100.0f64);
    let mut crop_h = use_signal(|| 100.0f64);
    let mut crop_drag_start = use_signal(|| None::<(f64, f64)>);
    // Click once to set the start corner, move, click again to close: no
    // mouse button held down, so the browser cannot start an image drag.
    let mut crop_selecting = use_signal(|| false);
    let mut crop_ratio = use_signal(|| 0.0f64);
    let mut crop_render = use_signal(|| (0.0f64, 0.0f64));
    let mut crop_natural = use_signal(|| (0u32, 0u32));
    let mut crop_source = use_signal(|| None::<EditSource>);

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
            image_error.set(None);
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
        restore_pending_uploads(attachments);
        image_error.set(None);
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
            image_error.set(None);
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

            // The handler rejects a send that cannot be prepared (not a
            // member, cooldown, size limit): keep the text so nothing is lost.
            if let Err(error) =
                handle_send_message.call((title, content, reply_ctx, poll, images))
            {
                crate::components::app::toasts::show_error(format!("Could not send: {error}"));
                return;
            }
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
                    ondragover: move |event: Event<dioxus::html::DragData>| {
                        event.prevent_default();
                    },
                    ondrop: move |event: Event<dioxus::html::DragData>| {
                        use dioxus::html::HasFileData;
                        event.prevent_default();
                        let files = event.files();
                        if files.is_empty() {
                            return;
                        }
                        let reply_target = replying_to
                            .read()
                            .as_ref()
                            .map(|reply| reply.message_id.clone());
                        let mode = *image_mode.peek();
                        let attachments = attachments;
                        let next_id = next_attachment_id;
                        spawn_local(async move {
                            let mut converted = Vec::new();
                            for data in files {
                                if let Some(file) = file_from_data(&data).await {
                                    converted.push(file);
                                }
                            }
                            add_attachment_files(converted, attachments, next_id, mode, reply_target);
                        });
                    },

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
                                dir: "auto",
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
                                        dir: "auto",
                                        placeholder: "Type your message...",
                                        value: "{message_text}",
                                        rows: "5",
                                        oninput: move |evt| {
                                            message_text.set(evt.value().to_string());
                                            schedule_save();
                                        },
                                        onpaste: move |event: Event<dioxus::html::ClipboardData>| {
                                            use dioxus_web::WebEventExt;
                                            let Some(web_event) = event.try_as_web_event() else {
                                                return;
                                            };
                                            let Ok(clipboard) = web_event
                                                .dyn_into::<web_sys::ClipboardEvent>()
                                            else {
                                                return;
                                            };
                                            let Some(data) = clipboard.clipboard_data() else {
                                                return;
                                            };
                                            let Some(files) = data.files() else {
                                                return;
                                            };
                                            let images: Vec<web_sys::File> = (0..files.length())
                                                .filter_map(|index| files.get(index))
                                                .filter(|file| file.type_().starts_with("image/"))
                                                .collect();
                                            if images.is_empty() {
                                                return;
                                            }
                                            event.prevent_default();
                                            let reply_target = replying_to
                                                .read()
                                                .as_ref()
                                                .map(|reply| reply.message_id.clone());
                                            add_attachment_files(
                                                images,
                                                attachments,
                                                next_attachment_id,
                                                *image_mode.peek(),
                                                reply_target,
                                            );
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
                            accept: "image/png,image/jpeg,image/webp,image/gif,image/heic,image/heif,image/avif",
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
                        div { class: "mt-2 border border-dashed border-border rounded-lg px-3 py-2 text-center text-xs text-text-muted",
                            "Drag images here, or paste them with Ctrl+V."
                        }
                        if let Some(error) = image_error.read().clone() {
                            p { class: "mt-1 text-xs text-red-400", "{error}" }
                        }
                        details { class: "mt-1",
                            summary { class: "text-xs text-text-muted cursor-pointer", "Developer: test a file" }
                            p { class: "text-xs text-text-muted mt-1",
                                "Loads a file through the same processing path as Attach image. Useful for HEIC and AVIF."
                            }
                            input {
                                id: "image-file-input-test",
                                r#type: "file",
                                accept: "image/png,image/jpeg,image/webp,image/gif,image/heic,image/heif,image/avif",
                                multiple: true,
                                class: "mt-1 block w-full text-xs text-text-muted",
                                onchange: move |_| {
                                    if let Some(files) = selected_files_from("image-file-input-test") {
                                        let reply_target = replying_to
                                            .read()
                                            .as_ref()
                                            .map(|reply| reply.message_id.clone());
                                        add_attachment_files(
                                            files,
                                            attachments,
                                            next_attachment_id,
                                            ImageMode::KeepOriginal,
                                            reply_target,
                                        );
                                    }
                                },
                            }
                        }
                        if *crate::components::app::PENDING_QUEUE_FULL.read() {
                            p { class: "mt-1 text-xs text-red-400",
                                "The durable queue is full (24 MiB): this image will not survive a reload."
                            }
                        }
                        {
                            let owned = crate::util::owned_images::list();
                            if !owned.is_empty() {
                                rsx! {
                                    div { class: "mt-2",
                                        p { class: "text-xs text-text-muted mb-1", "Your images" }
                                        div { class: "flex flex-wrap gap-2",
                                            for entry in owned.iter().take(8) {
                                                {
                                                    let image = entry.image.clone();
                                                    let instance = image.instance;
                                                    rsx! {
                                                        div {
                                                            key: "{instance:?}",
                                                            class: "flex items-center gap-1 border border-border rounded px-2 py-1",
                                                            TopicThumb { image: image.clone() }
                                                            button {
                                                                r#type: "button",
                                                                class: "text-xs text-text max-w-40 truncate",
                                                                title: "Attach this image again",
                                                                onclick: {
                                                                    let image = image.clone();
                                                                    move |_| {
                                                                        if attachments.read().iter().any(|attachment| {
                                                                            matches!(&attachment.state, AttachmentState::Ready(existing) if existing.instance == image.instance)
                                                                        }) {
                                                                            return;
                                                                        }
                                                                        let counter = *next_attachment_id.peek();
                                                                        next_attachment_id.set(counter + 1);
                                                                        attachments.with_mut(|list| {
                                                                            list.push(Attachment {
                                                                                id: format!("reuse-{counter}"),
                                                                                name: image.alt.clone(),
                                                                                alt: image.alt.clone(),
                                                                                nsfw: image.nsfw,
                                                                                state: AttachmentState::Ready(image.clone()),
                                                                            });
                                                                        });
                                                                    }
                                                                },
                                                                "{image.alt}"
                                                            }
                                                            button {
                                                                r#type: "button",
                                                                class: "text-[10px] text-text-muted hover:text-accent",
                                                                title: "Put it back on the network now",
                                                                onclick: move |_| crate::util::owned_images::renew_now(instance),
                                                                "Renew"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                rsx! {}
                            }
                        }
                        div { class: "flex items-center gap-2",
                            label { class: "text-xs text-text-muted", "Format" }
                            select {
                                class: "px-2 py-1 bg-neutral-900 border border-border rounded text-xs text-white",
                                style: "color-scheme: dark; background-color: #171717; color: #f5f5f5;",
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
                                    option {
                                        value: "{candidate.label()}",
                                        style: "background-color: #171717; color: #f5f5f5;",
                                        "{candidate.label()}"
                                    }
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
                                                if let Some((done, total)) = crate::components::app::UPLOAD_PROGRESS
                                                    .read()
                                                    .get(&attachment.id)
                                                    .copied()
                                                {
                                                    if total > 0 {
                                                        {format!(
                                                            "Uploading {}%...",
                                                            (done * 100 / total).min(100)
                                                        )}
                                                    } else {
                                                        "Uploading..."
                                                    }
                                                } else {
                                                    "Uploading..."
                                                }
                                            }
                                        },
                                        AttachmentState::Ready(image) => rsx! {
                                            span { class: "text-text-muted",
                                                "{image.width}x{image.height} · {image.bytes / 1024} KB"
                                            }
                                            select {
                                                class: "px-1 py-0.5 bg-neutral-900 border border-border rounded text-xs text-white",
                                                style: "color-scheme: dark; background-color: #171717; color: #f5f5f5;",
                                                title: "Width in the post",
                                                value: "{image.display}",
                                                onchange: {
                                                    let id = attachment.id.clone();
                                                    move |event| {
                                                        let value = event.value().parse::<u16>().unwrap_or(0);
                                                        let value = if value == 0 { 0 } else { value.clamp(25, 100) };
                                                        attachments.with_mut(|list| {
                                                            if let Some(slot) = list.iter_mut().find(|entry| entry.id == id) {
                                                                if let AttachmentState::Ready(image) = &mut slot.state {
                                                                    image.display = value;
                                                                }
                                                            }
                                                        });
                                                    }
                                                },
                                                option { value: "0", style: "background-color: #171717; color: #f5f5f5;", "Full" }
                                                option { value: "25", style: "background-color: #171717; color: #f5f5f5;", "25%" }
                                                option { value: "50", style: "background-color: #171717; color: #f5f5f5;", "50%" }
                                                option { value: "75", style: "background-color: #171717; color: #f5f5f5;", "75%" }
                                                option { value: "100", style: "background-color: #171717; color: #f5f5f5;", "100%" }
                                            }
                                            select {
                                                class: "px-1 py-0.5 bg-neutral-900 border border-border rounded text-xs text-white",
                                                style: "color-scheme: dark; background-color: #171717; color: #f5f5f5;",
                                                title: "Image position relative to the text",
                                                value: if image.placement == ImagePlacement::Before { "before" } else { "after" },
                                                onchange: {
                                                    let id = attachment.id.clone();
                                                    move |event| {
                                                        let placement = if event.value() == "before" { ImagePlacement::Before } else { ImagePlacement::After };
                                                        attachments.with_mut(|list| {
                                                            if let Some(slot) = list.iter_mut().find(|entry| entry.id == id) {
                                                                if let AttachmentState::Ready(image) = &mut slot.state {
                                                                    image.placement = placement;
                                                                }
                                                            }
                                                        });
                                                    }
                                                },
                                                option { value: "after", style: "background-color: #171717; color: #f5f5f5;", "After text" }
                                                option { value: "before", style: "background-color: #171717; color: #f5f5f5;", "Before text" }
                                            }
                                            select {
                                                class: "px-1 py-0.5 bg-neutral-900 border border-border rounded text-xs text-white",
                                                style: "color-scheme: dark; background-color: #171717; color: #f5f5f5;",
                                                title: "Horizontal alignment",
                                                value: match image.align {
                                                    ImageAlign::Left => "left",
                                                    ImageAlign::Center => "center",
                                                    ImageAlign::Right => "right",
                                                },
                                                onchange: {
                                                    let id = attachment.id.clone();
                                                    move |event| {
                                                        let align = match event.value().as_str() {
                                                            "left" => ImageAlign::Left,
                                                            "right" => ImageAlign::Right,
                                                            _ => ImageAlign::Center,
                                                        };
                                                        attachments.with_mut(|list| {
                                                            if let Some(slot) = list.iter_mut().find(|entry| entry.id == id) {
                                                                if let AttachmentState::Ready(image) = &mut slot.state {
                                                                    image.align = align;
                                                                }
                                                            }
                                                        });
                                                    }
                                                },
                                                option { value: "left", style: "background-color: #171717; color: #f5f5f5;", "Left" }
                                                option { value: "center", style: "background-color: #171717; color: #f5f5f5;", "Center" }
                                                option { value: "right", style: "background-color: #171717; color: #f5f5f5;", "Right" }
                                            }
                                            button {
                                                r#type: "button",
                                                class: "px-1 text-xs text-text-muted hover:text-accent",
                                                title: "Rotate right",
                                                onclick: {
                                                    let id = attachment.id.clone();
                                                    let state = attachment.state.clone();
                                                    let target = replying_to
                                                        .read()
                                                        .as_ref()
                                                        .map(|reply| reply.message_id.clone());
                                                    move |_| {
                                                        edit_attachment_from_row(
                                                            id.clone(),
                                                            state.clone(),
                                                            crate::util::image_processing::Transform::RotateRight,
                                                            attachments,
                                                            next_attachment_id,
                                                            target.clone(),
                                                            image_error,
                                                        )
                                                    }
                                                },
                                                "↻"
                                            }
                                            button {
                                                r#type: "button",
                                                class: "px-1 text-xs text-text-muted hover:text-accent",
                                                title: "Rotate left",
                                                onclick: {
                                                    let id = attachment.id.clone();
                                                    let state = attachment.state.clone();
                                                    let target = replying_to
                                                        .read()
                                                        .as_ref()
                                                        .map(|reply| reply.message_id.clone());
                                                    move |_| {
                                                        edit_attachment_from_row(
                                                            id.clone(),
                                                            state.clone(),
                                                            crate::util::image_processing::Transform::RotateLeft,
                                                            attachments,
                                                            next_attachment_id,
                                                            target.clone(),
                                                            image_error,
                                                        )
                                                    }
                                                },
                                                "↺"
                                            }
                                            button {
                                                r#type: "button",
                                                class: "px-1 text-xs text-text-muted hover:text-accent",
                                                title: "Crop to a square",
                                                onclick: {
                                                    let id = attachment.id.clone();
                                                    let state = attachment.state.clone();
                                                    let target = replying_to
                                                        .read()
                                                        .as_ref()
                                                        .map(|reply| reply.message_id.clone());
                                                    move |_| {
                                                        edit_attachment_from_row(
                                                            id.clone(),
                                                            state.clone(),
                                                            crate::util::image_processing::Transform::CropSquare,
                                                            attachments,
                                                            next_attachment_id,
                                                            target.clone(),
                                                            image_error,
                                                        )
                                                    }
                                                },
                                                "⧉"
                                            }
                                            button {
                                                r#type: "button",
                                                class: "px-1 text-[10px] text-text-muted hover:text-accent",
                                                title: "Crop to 16:9",
                                                onclick: {
                                                    let id = attachment.id.clone();
                                                    let state = attachment.state.clone();
                                                    let target = replying_to
                                                        .read()
                                                        .as_ref()
                                                        .map(|reply| reply.message_id.clone());
                                                    move |_| {
                                                        edit_attachment_from_row(
                                                            id.clone(),
                                                            state.clone(),
                                                            crate::util::image_processing::Transform::CropWide,
                                                            attachments,
                                                            next_attachment_id,
                                                            target.clone(),
                                                            image_error,
                                                        )
                                                    }
                                                },
                                                "16:9"
                                            }
                                            button {
                                                r#type: "button",
                                                class: "px-1 text-[10px] text-text-muted hover:text-accent",
                                                title: "Crop to 4:3",
                                                onclick: {
                                                    let id = attachment.id.clone();
                                                    let state = attachment.state.clone();
                                                    let target = replying_to
                                                        .read()
                                                        .as_ref()
                                                        .map(|reply| reply.message_id.clone());
                                                    move |_| {
                                                        edit_attachment_from_row(
                                                            id.clone(),
                                                            state.clone(),
                                                            crate::util::image_processing::Transform::CropClassic,
                                                            attachments,
                                                            next_attachment_id,
                                                            target.clone(),
                                                            image_error,
                                                        )
                                                    }
                                                },
                                                "4:3"
                                            }
                                            button {
                                                r#type: "button",
                                                class: "px-1 text-xs text-text-muted hover:text-accent",
                                                title: "Free crop: drag on the image",
                                                onclick: {
                                                    let id = attachment.id.clone();
                                                    let state = attachment.state.clone();
                                                    move |_| {
                                                        if let Some(source) = attachment_source(&id, &state) {
                                                            if let Some(url) = preview_url(&source.bytes, &source.mime) {
                                                                if let Some(old) = crop_url.read().clone() {
                                                                    let _ = web_sys::Url::revoke_object_url(&old);
                                                                }
                                                                crop_url.set(Some(url));
                                                                crop_target.set(Some(id.clone()));
                                                                crop_source.set(Some(source.clone()));
                                                                crop_x.set(0.0);
                                                                crop_y.set(0.0);
                                                                crop_w.set(100.0);
                                                                crop_h.set(100.0);
                                                                crop_ratio.set(0.0);
                                                                crop_drag_start.set(None);
                                                                crop_selecting.set(false);
                                                                crop_render.set((0.0, 0.0));
                                                                crop_natural.set((
                                                                    source.width,
                                                                    source.height,
                                                                ));
                                                            }
                                                        } else {
                                                            image_error.set(Some(
                                                                "The original bytes of this image are not on this device. Re-upload the file to edit it."
                                                                    .to_string(),
                                                            ));
                                                        }
                                                    }
                                                },
                                                "✂"
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
                                        title: if matches!(attachment.state, AttachmentState::Uploading) {
                                            "Cancel upload"
                                        } else {
                                            "Remove"
                                        },
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
                        if let Some(target) = crop_target.read().clone() {
                            div { class: "fixed inset-0 z-[70] bg-black/75 flex items-center justify-center p-4",
                                div { class: "bg-panel rounded-xl p-4 w-full max-w-3xl",
                                    h3 { class: "text-lg font-semibold text-text mb-2", "Crop image" }
                                    p { class: "text-xs text-text-muted mb-2",
                                        "Adjust the rectangle, then apply."
                                    }
                                    div { class: "relative inline-block max-w-full",
                                        if let Some(url) = crop_url.read().clone() {
                                            img {
                                                id: "crop-preview-image",
                                                src: "{url}",
                                                class: "block max-h-[55vh] w-auto mx-auto select-none cursor-crosshair",
                                                alt: "",
                                                draggable: "false",
                                                ondragstart: move |event| event.prevent_default(),
                                                onload: move |_| {
                                                    if let Some(window) = web_sys::window() {
                                                        if let Some(element) = window
                                                            .document()
                                                            .and_then(|document| document.get_element_by_id("crop-preview-image"))
                                                        {
                                                            let rect = element.get_bounding_client_rect();
                                                            crop_render.set((rect.width(), rect.height()));
                                                        }
                                                    }
                                                },
                                                onclick: move |event: Event<dioxus::html::MouseData>| {
                                                    let (render_w, render_h) = *crop_render.read();
                                                    if render_w <= 0.0 || render_h <= 0.0 {
                                                        return;
                                                    }
                                                    if *crop_selecting.read() {
                                                        // Second click: close the rectangle.
                                                        crop_selecting.set(false);
                                                        if *crop_w.read() < 1.0 || *crop_h.read() < 1.0 {
                                                            crop_x.set(0.0);
                                                            crop_y.set(0.0);
                                                            crop_w.set(100.0);
                                                            crop_h.set(100.0);
                                                        }
                                                        return;
                                                    }
                                                    let coordinates = event.element_coordinates();
                                                    let x = (coordinates.x / render_w * 100.0).clamp(0.0, 100.0);
                                                    let y = (coordinates.y / render_h * 100.0).clamp(0.0, 100.0);
                                                    crop_drag_start.set(Some((x, y)));
                                                    crop_x.set(x);
                                                    crop_y.set(y);
                                                    crop_w.set(1.0);
                                                    crop_h.set(1.0);
                                                    crop_selecting.set(true);
                                                },
                                                onmousemove: move |event: Event<dioxus::html::MouseData>| {
                                                    if !*crop_selecting.read() {
                                                        return;
                                                    }
                                                    let Some((start_x, start_y)) = *crop_drag_start.read() else {
                                                        return;
                                                    };
                                                    let (render_w, render_h) = *crop_render.read();
                                                    if render_w <= 0.0 || render_h <= 0.0 {
                                                        return;
                                                    }
                                                    let coordinates = event.element_coordinates();
                                                    let (left, top, width, height) =
                                                        crate::util::crop_math::drag_rect(
                                                            (start_x, start_y),
                                                            (coordinates.x, coordinates.y),
                                                            (render_w, render_h),
                                                            *crop_ratio.read(),
                                                            *crop_natural.read(),
                                                        );
                                                    crop_x.set(left);
                                                    crop_y.set(top);
                                                    crop_w.set(width.max(1.0));
                                                    crop_h.set(height.max(1.0));
                                                },
                                            }
                                        }
                                        div {
                                            class: "absolute border-2 border-accent bg-accent/25 pointer-events-none",
                                            style: "left: {crop_x}%; top: {crop_y}%; width: {crop_w}%; height: {crop_h}%;",
                                        }
                                    }
                                    p { class: "text-xs text-text-muted mt-2",
                                        "Click the starting corner, move the mouse, then click again to close the rectangle."
                                    }
                                    div { class: "flex flex-wrap gap-2 mt-2",
                                        button {
                                            r#type: "button",
                                            class: if *crop_ratio.read() == 0.0 { "px-2 py-1 text-xs rounded bg-accent text-white" } else { "px-2 py-1 text-xs rounded border border-border text-text" },
                                            onclick: move |_| crop_ratio.set(0.0),
                                            "Free"
                                        }
                                        button {
                                            r#type: "button",
                                            class: if (*crop_ratio.read() - 1.0).abs() < 0.01 { "px-2 py-1 text-xs rounded bg-accent text-white" } else { "px-2 py-1 text-xs rounded border border-border text-text" },
                                            onclick: move |_| {
                                                crop_ratio.set(1.0);
                                                let (nw, nh) = *crop_natural.read();
                                                if nw > 0 && nh > 0 {
                                                    let width = *crop_w.read();
                                                    let mut height = width * nw as f64 / nh as f64;
                                                    if *crop_y.read() + height > 100.0 {
                                                        height = 100.0 - *crop_y.read();
                                                    }
                                                    crop_h.set(height.max(1.0));
                                                }
                                            },
                                            "1:1"
                                        }
                                        button {
                                            r#type: "button",
                                            class: if (*crop_ratio.read() - 16.0 / 9.0).abs() < 0.01 { "px-2 py-1 text-xs rounded bg-accent text-white" } else { "px-2 py-1 text-xs rounded border border-border text-text" },
                                            onclick: move |_| {
                                                crop_ratio.set(16.0 / 9.0);
                                                let (nw, nh) = *crop_natural.read();
                                                if nw > 0 && nh > 0 {
                                                    let width = *crop_w.read();
                                                    let mut height = width * nw as f64 / (16.0 / 9.0 * nh as f64);
                                                    if *crop_y.read() + height > 100.0 {
                                                        height = 100.0 - *crop_y.read();
                                                    }
                                                    crop_h.set(height.max(1.0));
                                                }
                                            },
                                            "16:9"
                                        }
                                        button {
                                            r#type: "button",
                                            class: if (*crop_ratio.read() - 4.0 / 3.0).abs() < 0.01 { "px-2 py-1 text-xs rounded bg-accent text-white" } else { "px-2 py-1 text-xs rounded border border-border text-text" },
                                            onclick: move |_| {
                                                crop_ratio.set(4.0 / 3.0);
                                                let (nw, nh) = *crop_natural.read();
                                                if nw > 0 && nh > 0 {
                                                    let width = *crop_w.read();
                                                    let mut height = width * nw as f64 / (4.0 / 3.0 * nh as f64);
                                                    if *crop_y.read() + height > 100.0 {
                                                        height = 100.0 - *crop_y.read();
                                                    }
                                                    crop_h.set(height.max(1.0));
                                                }
                                            },
                                            "4:3"
                                        }
                                    }
                                    div { class: "flex justify-end gap-2 mt-4",
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1.5 bg-surface hover:bg-surface-hover border border-border rounded-lg text-sm text-text",
                                            onclick: move |_| {
                                                if let Some(url) = crop_url.read().clone() {
                                                    let _ = web_sys::Url::revoke_object_url(&url);
                                                }
                                                crop_target.set(None);
                                                crop_url.set(None);
                                                crop_selecting.set(false);
                                            },
                                            "Cancel"
                                        }
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1.5 bg-accent hover:bg-accent-hover text-white rounded-lg text-sm",
                                            onclick: {
                                                let target = target.clone();
                                                move |_| {
                                                    let reply_target = replying_to
                                                        .read()
                                                        .as_ref()
                                                        .map(|reply| reply.message_id.clone());
                                                    if let Some(source) = crop_source.read().clone() {
                                                        edit_attachment(
                                                            target.clone(),
                                                            source,
                                                            crate::util::image_processing::Transform::CropRect {
                                                                x: *crop_x.read() as u16,
                                                                y: *crop_y.read() as u16,
                                                                width: (*crop_w.read() as u16).clamp(1, 100),
                                                                height: (*crop_h.read() as u16).clamp(1, 100),
                                                            },
                                                            attachments,
                                                            next_attachment_id,
                                                            reply_target,
                                                        );
                                                    }
                                                    if let Some(url) = crop_url.read().clone() {
                                                        let _ = web_sys::Url::revoke_object_url(&url);
                                                    }
                                                    crop_target.set(None);
                                                    crop_url.set(None);
                                                    crop_source.set(None);
                                                    crop_selecting.set(false);
                                                }
                                            },
                                            "Apply crop"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}



