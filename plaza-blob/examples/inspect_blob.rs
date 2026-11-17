//! Print a blob state: retired flag, payload size and chunk list.
use plaza_blob_core::BlobStateV1;

fn main() {
    let path = std::env::args().nth(1).expect("state file");
    let bytes = std::fs::read(&path).expect("read");
    let state: BlobStateV1 = ciborium::from_reader(&bytes[..]).expect("decode");
    println!(
        "retired={} data={} chunks={}",
        state.retired,
        state.data.len(),
        state.chunks.len()
    );
    for chunk in state.chunks.iter().take(8) {
        println!(
            "chunk {:?} bytes={} sha={:?}",
            chunk.instance, chunk.bytes, chunk.sha256
        );
    }
}
