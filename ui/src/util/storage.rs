//! Estimated sizes of the data this device keeps in the delegate store.

use crate::components::app::BOARDS;
use dioxus::prelude::ReadableExt;

pub struct StorageSizes {
    pub boards: usize,
    pub images: usize,
    pub image_count: usize,
    pub queues: usize,
    pub queued_count: usize,
}

pub fn sizes() -> StorageSizes {
    let boards = BOARDS.read();
    let mut buffer = Vec::new();
    let boards_len = ciborium::ser::into_writer(&*boards, &mut buffer)
        .map(|_| buffer.len())
        .unwrap_or(0);
    let images: usize = boards
        .owned_images
        .iter()
        .map(|entry| {
            entry.state.len()
                + entry
                    .chunks
                    .iter()
                    .map(|chunk| chunk.state.len())
                    .sum::<usize>()
        })
        .sum();
    let mut queued_count = 0;
    let mut queues = 0;
    for board in boards.map.values() {
        for upload in &board.pending_uploads {
            queued_count += 1;
            queues += upload.bytes.len() + upload.name.len() + 64;
        }
    }
    StorageSizes {
        boards: boards_len,
        images,
        image_count: boards.owned_images.len(),
        queues,
        queued_count,
    }
}

pub fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
