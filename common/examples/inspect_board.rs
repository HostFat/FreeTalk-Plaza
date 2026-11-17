//! Print the image references of a board state, for debugging.
use plaza_core::ChatBoardStateV1;

fn main() {
    let path = std::env::args().nth(1).expect("state file");
    let bytes = std::fs::read(&path).expect("read");
    let state: ChatBoardStateV1 = ciborium::from_reader(&bytes[..]).expect("decode");
    for message in &state.recent_messages.messages {
        for image in &message.message.images {
            println!(
                "message {:?}: instance {:?} thumb {:?}",
                message.id(),
                image.instance,
                image.thumb
            );
        }
    }
}
