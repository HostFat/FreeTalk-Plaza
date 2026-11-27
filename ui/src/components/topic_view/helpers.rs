//! Mention, attachment, and formatting helpers for `TopicView`.

use super::*;

pub(super) fn refresh_topic_reply_mentions(mut mention_autocomplete: Signal<Option<MentionAutocomplete>>) {
    #[cfg(target_arch = "wasm32")]
    {
        let next = crate::util::mentions::textarea_context(TOPIC_REPLY_INPUT_ID);
        mention_autocomplete.set(next);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = &mut mention_autocomplete;
    }
}

pub(super) fn open_topic_image_picker() {
    if let Some(document) = web_sys::window().and_then(|window| window.document()) {
        if let Some(element) = document.get_element_by_id(TOPIC_IMAGE_INPUT_ID) {
            if let Ok(input) = element.dyn_into::<web_sys::HtmlInputElement>() {
                input.click();
            }
        }
    }
}

pub(super) fn selected_topic_files() -> Option<Vec<web_sys::File>> {
    let document = web_sys::window()?.document()?;
    let input = document
        .get_element_by_id(TOPIC_IMAGE_INPUT_ID)?
        .dyn_into::<web_sys::HtmlInputElement>()
        .ok()?;
    let files = input.files()?;
    let list: Vec<web_sys::File> = (0..files.length())
        .filter_map(|index| files.get(index))
        .collect();
    input.set_value("");
    Some(list)
}

pub(super) fn attach_topic_files(
    files: Vec<web_sys::File>,
    owner: ed25519_dalek::VerifyingKey,
    section_id: Option<MessageId>,
    mut attachments: Signal<Vec<TopicAttachment>>,
    mut next_id: Signal<u64>,
) {
    let Some(board_data) = BOARDS.read().map.get(&owner).cloned() else {
        return;
    };
    let secret = board_data.image_upload_secret(section_id.as_ref(), None);
    let now = crate::util::get_current_system_time()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);

    for file in files {
        if attachments.read().len() >= MAX_IMAGES_PER_POST {
            break;
        }
        let counter = *next_id.peek();
        let id = format!("topic-{now}-{counter}");
        next_id.set(counter + 1);
        let name = file.name();
        attachments.with_mut(|list| {
            list.push(TopicAttachment {
                id: id.clone(),
                name: name.clone(),
                state: TopicAttachmentState::Uploading,
            });
        });
        let board_for_upload = board_data.clone();
        spawn_local(async move {
            match prepare_image(&file, ImageMode::StripMetadata).await {
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
                    let result = crate::util::uploads::upload_pending(
                        &board_for_upload,
                        &record,
                        None,
                    )
                    .await;
                    match result {
                        Ok((image, copy)) => {
                            if let Some(copy) = copy {
                                crate::util::owned_images::record(&image, copy);
                            }
                            attachments.with_mut(|list| {
                                if let Some(slot) = list.iter_mut().find(|item| item.id == id) {
                                    slot.state = TopicAttachmentState::Ready(image);
                                }
                            });
                        }
                        Err(err) => {
                            attachments.with_mut(|list| {
                                if let Some(slot) = list.iter_mut().find(|item| item.id == id) {
                                    slot.state = TopicAttachmentState::Failed(err);
                                }
                            });
                        }
                    }
                }
                Err(err) => {
                    attachments.with_mut(|list| {
                        if let Some(slot) = list.iter_mut().find(|item| item.id == id) {
                            slot.state = TopicAttachmentState::Failed(err);
                        }
                    });
                }
            }
        });
    }
}

pub(super) fn reactor_names_map(
    board: &crate::board_data::BoardData,
    reactions: &BTreeMap<String, Vec<MemberId>>,
) -> HashMap<MemberId, String> {
    let mut names = HashMap::new();
    for members in reactions.values() {
        for member in members {
            names.entry(*member).or_insert_with(|| {
                board
                    .display_nickname(*member)
                    .unwrap_or_else(|| short_id(*member))
            });
        }
    }
    names
}

pub(super) fn short_id(id: MemberId) -> String {
    id.to_string().chars().take(8).collect()
}

pub(super) fn short_topic(id: MessageId) -> String {
    id.to_string().chars().take(8).collect()
}

pub(super) fn format_time(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    crate::util::format_utc_as_local_time(ms)
}

pub(super) fn format_full_time(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    crate::util::format_utc_as_full_datetime(ms)
}
