//! Print how many boards a Plaza backup file contains.

fn main() {
    let path = std::env::args().nth(1).expect("usage: inspect_backup <file>");
    let bytes = std::fs::read(&path).expect("read backup");
    let value: ciborium::value::Value =
        ciborium::de::from_reader(&bytes[..]).expect("decode backup");
    let Some(root) = value.as_map() else {
        println!("not a map");
        return;
    };
    for (key, value) in root {
        if key.as_text() == Some("boards") {
            let Some(boards) = value.as_map() else { continue };
            for (board_key, board_value) in boards {
                if board_key.as_text() == Some("map") {
                    let count = board_value.as_map().map(|map| map.len()).unwrap_or(0);
                    println!("boards in backup: {count}");
                }
            }
        }
    }
}
