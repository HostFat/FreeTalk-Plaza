use crate::components::app::sync_info::SYNC_INFO;
use dioxus::logger::tracing::info;
use dioxus::prelude::ReadableExt;
use freenet_stdlib::prelude::ContractKey;

pub fn handle_update_response(key: ContractKey, summary: Vec<u8>) {
    let summary_len = summary.len();
    let owner = SYNC_INFO
        .read()
        .get_owner_vk_for_instance_id(key.id());
    info!("Received update response for key {key}, summary length {summary_len}");
    if let Some(owner) = owner {
        // The node accepted the update: the revisions it carried are on the
        // network. Defer the signal writes like every other response handler.
        crate::util::defer(move || {
            SYNC_INFO.with_mut(|info| info.mark_acked(&owner));
            crate::components::app::confirm_pending_posts(owner);
        });
    }
}
