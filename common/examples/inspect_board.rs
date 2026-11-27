//! Print sections and topic entries of a board state, for debugging.
use plaza_core::ChatBoardStateV1;

fn main() {
    let path = std::env::args().nth(1).expect("state file");
    let bytes = std::fs::read(&path).expect("read");
    let state: ChatBoardStateV1 = ciborium::from_reader(&bytes[..]).expect("decode");
    println!(
        "mode={:?} members={} sections={} topics={}",
        state.mode,
        state.members.members.len(),
        state.sections.sections.len(),
        state.topics.entries.len(),
    );
    for section in &state.sections.sections {
        println!(
            "section {:?}: name={:?} deleted={} contract={:?}",
            section.section.id,
            section.section.name,
            section.section.deleted,
            section.section.contract,
        );
    }
    for topic in &state.topics.entries {
        println!(
            "topic {:?}: section={:?} author={:?} part={}",
            topic.entry.topic_id,
            topic.entry.section,
            topic.entry.author,
            topic.entry.part,
        );
    }
}
