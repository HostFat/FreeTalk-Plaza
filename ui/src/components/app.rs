pub mod chat_delegate;
pub mod dm_contract;
pub mod dm_delegate;
pub mod section_contract;
pub mod topic_contract;
pub mod document_title;
pub mod freenet_api;
pub mod notifications;
pub mod receive_times;
pub mod sync_info;
pub mod toasts;

use super::{
    admin_view::AdminView, board_list::BoardList, conversation::Conversation, members::MembersView,
    top_bar::TopBar,
};
use crate::board_data::{Boards, CurrentBoard};
use crate::components::about_modal::AboutModal;
use crate::components::app::document_title::DocumentTitleUpdater;
use crate::components::app::freenet_api::freenet_synchronizer::SynchronizerMessage;
use crate::components::app::freenet_api::freenet_synchronizer::SynchronizerStatus;
use crate::components::app::freenet_api::FreenetSynchronizer;
use crate::components::board_list::create_board_modal::CreateBoardModal;
use crate::components::board_list::edit_board_modal::EditBoardModal;
use crate::components::board_list::receive_invitation_modal::ReceiveInvitationModal;
use crate::components::category_create_modal::CategoryCreateModal;
use crate::components::members::member_info_modal::MemberInfoModal;
use crate::components::members::Invitation;
use crate::components::messages_view::{DM_JOIN_PREFILL, MESSAGES_OPEN};
use crate::components::notifications_view::NotificationsView;
use crate::components::posts_view::{PostsView, SinglePostView};
use crate::components::profile_view::ProfileView;
use crate::components::search_view::SearchView;
use crate::invites::PendingInvites;
use dioxus::document::{Link, Stylesheet};
use dioxus::logger::tracing::{debug, error, info};
use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use freenet_stdlib::client_api::{ClientRequest, WebApi};
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;
use std::rc::Rc;
use wasm_bindgen_futures::spawn_local;
use web_sys::window;

/// Application routes
#[derive(Clone, Debug, PartialEq, Routable)]
#[rustfmt::skip]
pub enum Route {
    #[route("/")]
    Home,
    #[route("/invite/:invite_code")]
    Invite { invite_code: String },
    #[route("/join/:token")]
    JoinBoard { token: String },
    #[route("/enable-topics")]
    EnableTopics,
    #[route("/enable-sections")]
    EnableSections,
    #[route("/test-reset")]
    TestReset,
    #[route("/dm/join/:contract_id/:token/:key_version/:key_b58")]
    DmJoin {
        contract_id: String,
        token: String,
        key_version: String,
        key_b58: String,
    },
    #[route("/view/:board_id")]
    ViewOnly { board_id: String },
    #[route("/board/:board_id")]
    Posts { board_id: String },
    #[route("/board/:board_id/post/:post_id")]
    Post { board_id: String, post_id: String },
    #[route("/board/:board_id/topic/:topic_id")]
    Topic { board_id: String, topic_id: String },
    #[route("/board/:board_id/category/:category_id")]
    PostsInCategory { board_id: String, category_id: String },
    #[route("/board/:board_id/conversation")]
    ConversationView { board_id: String },
    #[route("/board/:board_id/admin")]
    Admin { board_id: String },
    #[route("/board/:board_id/admin/banned")]
    AdminBanned { board_id: String },
    #[route("/board/:board_id/admin/moderation")]
    AdminModeration { board_id: String },
    #[route("/board/:board_id/admin/structure")]
    AdminStructure { board_id: String },
    #[route("/board/:board_id/admin/audit")]
    AdminAudit { board_id: String },
    #[route("/board/:board_id/admin/trash")]
    AdminTrash { board_id: String },
    #[route("/board/:board_id/purge/:post_id")]
    AdminPurge { board_id: String, post_id: String },
    #[route("/board/:board_id/admin/roles")]
    AdminRoles { board_id: String },
    #[route("/board/:board_id/admin/links")]
    AdminLinks { board_id: String },
    #[route("/board/:board_id/admin/ownership")]
    AdminOwnership { board_id: String },
    #[route("/board/:board_id/members")]
    Members { board_id: String },
    #[route("/board/:board_id/search")]
    Search { board_id: String },
    #[route("/board/:board_id/notifications")]
    Notifications { board_id: String },
    #[route("/board/:board_id/member/:member_key")]
    Profile {
        board_id: String,
        member_key: String,
    },
    #[route("/:..route")]
    NotFound { route: Vec<String> },
}

pub static BOARDS: GlobalSignal<Boards> = Global::new(initial_boards);

/// Confirmed upload steps per attachment, while an upload runs.
pub static UPLOAD_PROGRESS: GlobalSignal<std::collections::HashMap<String, (usize, usize)>> =
    Global::new(std::collections::HashMap::new);

/// True when the durable upload queue refused a file because of its cap.
pub static PENDING_QUEUE_FULL: GlobalSignal<bool> = Global::new(|| false);

/// Messages this client sent that the network has not confirmed yet, mapped to
/// the board they belong to so a confirmation clears the right badges.
pub static PENDING_POSTS: GlobalSignal<std::collections::HashMap<MessageId, VerifyingKey>> =
    Global::new(std::collections::HashMap::new);

/// Drop the pending marker of every message on a board the node just confirmed.
pub fn confirm_pending_posts(board: VerifyingKey) {
    PENDING_POSTS.with_mut(|pending| pending.retain(|_, owner| *owner != board));
}

/// Set once the boards stored in the delegate have been read (or the delegate
/// answered that it has none). Until then `BOARDS` is empty only because the
/// load has not finished, and persisting it would overwrite real data.
pub static BOARDS_LOADED: GlobalSignal<bool> = Global::new(|| false);

/// True when the delegate we loaded from actually contained boards. Used to
/// refuse writing an empty map over real data if a load ever fails validation.
pub static DELEGATE_HAD_BOARDS: GlobalSignal<bool> = Global::new(|| false);

pub static CURRENT_BOARD: GlobalSignal<CurrentBoard> =
    Global::new(|| CurrentBoard { owner_key: None });

pub static MEMBER_INFO_MODAL: GlobalSignal<MemberInfoModalSignal> =
    Global::new(|| MemberInfoModalSignal { member: None });

/// Invite token caught by the document-level click interceptor. App consumes
/// it and routes in place so the open topic and composer stay alive.
pub static INTERCEPTED_JOIN_TOKEN: GlobalSignal<Option<String>> = Global::new(|| None);

/// The topic view stays pinned to the latest reply until the reader scrolls up.
pub static CONVERSATION_PINNED: GlobalSignal<bool> = Global::new(|| true);
/// Whether the "About FreeTalk Plaza" panel is open.
pub static ABOUT_MODAL: GlobalSignal<bool> = Global::new(|| false);
pub static EDIT_BOARD_MODAL: GlobalSignal<EditBoardModalSignal> =
    Global::new(|| EditBoardModalSignal { board: None });
pub static CREATE_BOARD_MODAL: GlobalSignal<CreateBoardModalSignal> =
    Global::new(|| CreateBoardModalSignal { show: false });
pub static PENDING_INVITES: GlobalSignal<PendingInvites> = Global::new(PendingInvites::new);
pub static SYNC_STATUS: GlobalSignal<SynchronizerStatus> =
    Global::new(|| SynchronizerStatus::Connecting);
pub static SYNCHRONIZER: GlobalSignal<FreenetSynchronizer> = Global::new(FreenetSynchronizer::new);
/// The client API is shared behind an async mutex: its users await their turn
/// instead of blocking the single-threaded UI while another task is sending.
pub type SharedWebApi = Rc<futures::lock::Mutex<WebApi>>;
pub static WEB_API: GlobalSignal<Option<SharedWebApi>> = Global::new(|| None);

/// Send one request through the shared client API.
pub async fn send_client_request(
    request: ClientRequest<'static>,
) -> Result<(), freenet_stdlib::client_api::Error> {
    let Some(api) = WEB_API.read().clone() else {
        return Err(freenet_stdlib::client_api::Error::ConnectionClosed);
    };
    let mut api = api.lock().await;
    api.send(request).await
}
pub static AUTH_TOKEN: GlobalSignal<Option<String>> = Global::new(|| None);

// Tracks which boards need to be synced due to USER actions (not network updates)
// This prevents infinite loops where network responses trigger more syncs
pub static NEEDS_SYNC: GlobalSignal<std::collections::HashSet<VerifyingKey>> =
    Global::new(std::collections::HashSet::new);

/// Bumped by the periodic housekeeping tick so the sync chip can re-evaluate
/// its timeout even when no board state changed.
pub static SYNC_TICK: GlobalSignal<u64> = Global::new(|| 0);

/// Images of one message in the full-screen viewer, and the open index.
#[derive(Clone, PartialEq)]
pub struct LightboxState {
    pub images: Vec<plaza_core::board_state::images::ImageRef>,
    pub index: usize,
}

pub static LIGHTBOX: GlobalSignal<Option<LightboxState>> = Global::new(|| None);

/// Tracks the current category being viewed (for auto-parenting new posts/categories)
pub static CURRENT_CATEGORY: GlobalSignal<CurrentCategoryContext> =
    Global::new(|| CurrentCategoryContext::default());

/// Tracks the single post being viewed, so the top-bar composer replies to it.
pub static CURRENT_POST: GlobalSignal<CurrentPostContext> =
    Global::new(|| CurrentPostContext::default());

/// Current hash route, used to highlight the active top-bar tab.
pub static CURRENT_HASH: GlobalSignal<String> = Global::new(String::new);

/// Bumped by "New post" buttons elsewhere in the app to open the shared
/// composer in the top bar (which already knows the current category).
pub static COMPOSE_REQUEST: GlobalSignal<u64> = Global::new(|| 0);

/// Group id (as a string) to scroll to after returning to the home page.
pub static SCROLL_TO_GROUP: GlobalSignal<Option<String>> = Global::new(|| None);

/// A post selected for quoting. The composer drains the collection and turns
/// every entry into a quoted block, so several posts can be quoted at once.
#[derive(Clone, PartialEq)]
pub struct QuoteRequest {
    pub target: MessageId,
    pub author: String,
    pub preview: String,
    pub text: String,
}
pub static QUOTE_COLLECTION: GlobalSignal<Vec<QuoteRequest>> = Global::new(Vec::new);

/// Post the report modal is open for.
pub static REPORT_TARGET: GlobalSignal<Option<MessageId>> = Global::new(|| None);

/// Context for the currently viewed category
#[derive(Clone, Default)]
pub struct CurrentCategoryContext {
    /// The category message ID being viewed
    pub category_id: Option<MessageId>,
    /// Category name (for reply preview)
    pub category_name: Option<String>,
    /// Author name of the category (for reply context)
    pub author_name: Option<String>,
}

/// The single post currently open, used as the reply target of the top bar.
#[derive(Clone, PartialEq, Default)]
pub struct CurrentPostContext {
    pub message_id: Option<MessageId>,
    pub author_name: Option<String>,
    pub preview: Option<String>,
}

/// Mark a board as needing sync, deferred via setTimeout(0).
///
/// IMPORTANT: Writing to NEEDS_SYNC triggers a Dioxus use_effect synchronously,
/// which cascades into ProcessBoards → BOARDS.read() and other signal reads.
/// If called while any signal is borrowed, this causes a RefCell re-entrant
/// borrow panic in WASM (especially on Firefox mobile).
///
/// Uses crate::util::defer() to break out of the WASM call stack entirely,
/// ensuring the write happens in a completely clean execution context.
/// Test-only UI mode: `?view=member` hides owner/admin controls in this tab
/// without touching keys or state. Used to check the normal-member UI on a
/// single-node delegate, which is shared by every origin of that node.
pub static TEST_VIEW_MEMBER: GlobalSignal<bool> = Signal::global(|| false);

pub fn view_as_member() -> bool {
    *TEST_VIEW_MEMBER.read()
}

pub fn mark_needs_sync(board_key: ed25519_dalek::VerifyingKey) {
    crate::util::defer(move || {
        // Count the change so the sync chip can wait for the node's answer.
        sync_info::SYNC_INFO.with_mut(|info| info.mark_local_change(&board_key));
        NEEDS_SYNC.write().insert(board_key);
        // Persist the change now. The periodic tick can be up to a minute
        // away, and a reload in that window used to lose the action.
        crate::util::safe_spawn_local(async {
            if let Err(error) = chat_delegate::save_boards_and_wait().await {
                dioxus::logger::tracing::warn!("Could not save boards: {error}");
            }
        });
    });
}

static ACTIVITY_SYNC: std::sync::Mutex<Vec<ed25519_dalek::VerifyingKey>> =
    std::sync::Mutex::new(Vec::new());
static ACTIVITY_SAVE: std::sync::Mutex<Vec<ed25519_dalek::VerifyingKey>> =
    std::sync::Mutex::new(Vec::new());

/// Persist an activity-only board change now, but coalesce its network update.
/// A busy topic can receive many replies in a few seconds; sending one board
/// delta per reply would make the board contract the bottleneck.
pub fn mark_needs_sync_later(
    board_key: ed25519_dalek::VerifyingKey,
    delay: std::time::Duration,
) {
    crate::util::defer(move || {
        {
            let mut scheduled = ACTIVITY_SAVE.lock().unwrap();
            if !scheduled.contains(&board_key) {
                scheduled.push(board_key);
                crate::util::safe_spawn_local(async move {
                    crate::util::sleep(std::time::Duration::from_secs(1)).await;
                    {
                        let mut scheduled = ACTIVITY_SAVE.lock().unwrap();
                        scheduled.retain(|key| *key != board_key);
                    }
                    if let Err(error) = chat_delegate::save_boards_and_wait().await {
                        dioxus::logger::tracing::warn!("Could not save boards: {error}");
                    }
                });
            }
        }
        {
            let mut scheduled = ACTIVITY_SYNC.lock().unwrap();
            if scheduled.contains(&board_key) {
                return;
            }
            scheduled.push(board_key);
        }
        crate::util::safe_spawn_local(async move {
            crate::util::sleep(delay).await;
            {
                let mut scheduled = ACTIVITY_SYNC.lock().unwrap();
                scheduled.retain(|key| *key != board_key);
            }
            mark_needs_sync(board_key);
        });
    });
}

/// Send the queued user changes to the synchronizer and persist the boards.
/// Safe to call when the queue is empty.
pub fn flush_pending_sync() {
    if NEEDS_SYNC.read().is_empty() {
        return;
    }
    let sender = SYNCHRONIZER.read().get_message_sender();
    match sender.unbounded_send(SynchronizerMessage::ProcessBoards) {
        Ok(()) => {
            NEEDS_SYNC.write().clear();
            wasm_bindgen_futures::spawn_local(async {
                if let Err(error) = chat_delegate::save_boards_to_delegate().await {
                    log::error!("Failed to save boards to delegate: {error}");
                }
            });
        }
        Err(error) => {
            log::error!("Failed to send ProcessBoards message: {error}");
        }
    }
}

// Build metadata from build.rs
const BUILD_TIMESTAMP: &str = env!("BUILD_TIMESTAMP_ISO");
const GIT_COMMIT: &str = env!("GIT_COMMIT_HASH");

#[component]
pub fn App() -> Element {
    info!(
        "FreeTalk Plaza UI loaded - Built: {} | Commit: {}",
        BUILD_TIMESTAMP, GIT_COMMIT
    );

    // Capture the Dioxus runtime for use in defer()/setTimeout callbacks.
    // Must be called from within a Dioxus component where the runtime is active.
    crate::util::capture_runtime();
    crate::components::app::topic_contract::start_topic_outbox();
    #[cfg(all(feature = "example-data", target_arch = "wasm32"))]
    crate::test_hooks::install();

    // Chips are raw HTML inside message bodies, so delegate clicks at the
    // document level. Idempotent; safe on every render.
    crate::components::mention_click_interceptor::install_mention_click_interceptor();
    crate::components::invite_click_interceptor::install_invite_click_interceptor();

    // The app runs in a sandboxed iframe inside the Freenet shell: keep the
    // shell's address bar in sync with the app route so refreshes and copied
    // links point at the same page.
    use_effect(move || {
        crate::util::install_shell_hash_bridge_once();
    });

    // Get auth token from window global (injected by Freenet gateway)
    // This is synchronous - no network request needed
    get_auth_token_from_window();

    // Start synchronizer - auth token is already available
    spawn_local(async {
        debug!("Starting FreenetSynchronizer from App component");
        // Note: The synchronizer will set up the chat delegate after connection is established
        let mut synchronizer = SYNCHRONIZER.write();
        synchronizer.start().await;
    });

    // The DM delegate follows the active profile. The connection may come up
    // while the app is still on the home page, so trigger initialization when
    // a board becomes current.
    use_effect(move || {
        if CURRENT_BOARD.read().owner_key.is_some() {
            dm_delegate::ensure_identity_for_active_board();
        }
    });

    // Finish posts whose images were still uploading when the page closed.
    use_effect(move || {
        if *BOARDS_LOADED.read() {
            crate::util::pending_send::resume_all();            // Once the board state has settled, retire own uploads that no
            // board references anymore.
            crate::util::safe_spawn_local(async {
                crate::util::sleep(std::time::Duration::from_secs(60)).await;
                if CURRENT_BOARD.read().owner_key.is_some() {
                    crate::util::owned_images::retire_unused(false);
                }
            });
        }
    });

    // Developer flag for the topic-contract UI: `?topics=1` makes the next
    // boards keep an index instead of the legacy message list.
    use_effect(move || {
        if *BOARDS_LOADED.read() {
            enable_topic_boards_from_query();
        }
    });

    // Restore cached section indexes before the network GETs finish, so the
    // board list and search show the last known content immediately.
    use_effect(move || {
        if *BOARDS_LOADED.read() {
            crate::util::safe_spawn_local(
                crate::components::app::section_contract::load_persisted_section_boards(),
            );
        }
    });

    // Section children are needed by the board list, search, notifications and
    // moderation, so load them for every route of a sectioned board.
    use_effect(move || {
        let current = CURRENT_BOARD.read();
        let Some(owner) = current.owner_key else {
            return;
        };
        let sections = {
            let boards = BOARDS.read();
            let Some(board) = boards.map.get(&owner) else {
                return;
            };
            if board.board_state.mode
                != plaza_core::board_state::BoardModeV1::SectionedTopicIndex
            {
                return;
            }
            board
                .board_state
                .sections
                .sections
                .iter()
                .filter_map(|entry| entry.section.contract.map(|_| entry.section.id))
                .collect::<Vec<_>>()
        };
        for section in sections {
            crate::util::safe_spawn_local(async move {
                let _ = crate::components::app::section_contract::load_section_board(
                    owner, section,
                )
                .await;
            });
        }
    });

    // If a GET or a restore sets CURRENT_BOARD before the delegate map is
    // loaded, the value may be the current owner or profile key. Once the map
    // arrives, resolve it back to the map key so the board renders.
    use_effect(move || {
        let current = CURRENT_BOARD.read().owner_key;
        let Some(current) = current else {
            return;
        };
        let resolved = {
            let boards = BOARDS.read();
            if boards.map.contains_key(&current) {
                return;
            }
            boards
                .map
                .iter()
                .find(|(map_key, board)| {
                    **map_key == current
                        || board.owner_key().verifying_key() == current
                        || board.current_owner_key() == current
                        || board.self_sk.verifying_key() == current
                        || board.owner_vk == current
                })
                .map(|(map_key, _)| *map_key)
        };
        if let Some(resolved) = resolved {
            select_board(Some(resolved));
        }
    });

    // Watch CURRENT_BOARD and navigate if URL doesn't match
    // This handles a board chosen from the list (and sync setting the current board):
    // CURRENT_BOARD changes, and the URL follows. The startup restore from the
    // delegate is gone, so opening the root URL keeps CURRENT_BOARD empty and
    // nothing navigates.
    use_effect(move || {
        let current_board = CURRENT_BOARD.read();
        if let Some(owner_key) = current_board.owner_key {
            let board_id = bs58::encode(owner_key.as_bytes()).into_string();

            // Check if URL already shows this board to avoid race conditions with regular navigation
            let url_matches = if let Some(window) = window() {
                if let Ok(hash) = window.location().hash() {
                    // Invite, join and spectator routes own the screen: a board
                    // already loaded in the background must not replace them.
                    let guest_route = hash.starts_with("#/join/")
                        || hash.starts_with("#/view/")
                        || hash.starts_with("#/invite/");
                    guest_route || hash.contains(&format!("/board/{}", board_id))
                } else {
                    false
                }
            } else {
                false
            };

            if !url_matches {
                debug!(
                    "CURRENT_BOARD changed to {} but URL doesn't match, navigating",
                    board_id
                );
                if let Some(window) = window() {
                    if let Err(e) = window.location().set_hash(&format!("#/board/{}", board_id)) {
                        error!("Failed to navigate to board: {:?}", e);
                    }
                }
            }
        }
    });

    #[cfg(not(feature = "no-sync"))]
    {
        // The synchronizer is now started in the auth token effect

        // Watch NEEDS_SYNC signal for USER-initiated changes only
        // This prevents infinite loops from network response updates to boards
        use_effect(move || {
            let boards_needing_sync = NEEDS_SYNC.read().clone();

            if !boards_needing_sync.is_empty() {
                info!(
                    "User changes detected for {} boards, triggering synchronization",
                    boards_needing_sync.len()
                );

                // Get all the data we need upfront to avoid nested borrows
                let message_sender = SYNCHRONIZER.read().get_message_sender();
                let has_boards = !BOARDS.read().map.is_empty();
                let has_invitations = !PENDING_INVITES.read().map.is_empty();

                if has_boards || has_invitations {
                    info!("Sending ProcessBoards message to synchronizer, has_boards={}, has_invitations={}", has_boards, has_invitations);

                    if let Err(e) =
                        message_sender.unbounded_send(SynchronizerMessage::ProcessBoards)
                    {
                        error!("Failed to send ProcessBoards message: {}", e);
                    } else {
                        info!("ProcessBoards message sent successfully");

                        // Clear the sync queue after successfully sending message
                        NEEDS_SYNC.write().clear();
                    }

                    // Also save boards to delegate when they change
                    // Use spawn_local to avoid blocking the UI thread
                    spawn_local(async {
                        if let Err(e) = chat_delegate::save_boards_to_delegate().await {
                            error!("Failed to save boards to delegate: {}", e);
                        }
                    });
                } else {
                    debug!("No boards to synchronize");
                    // Clear the queue even if there's nothing to sync
                    NEEDS_SYNC.write().clear();
                }
            }
        });

        info!("FreenetSynchronizer setup complete");
    }

    rsx! {
        // Favicon
        Link { rel: "icon", r#type: "image/svg+xml", href: asset!("/assets/plaza_logo.svg") }
        // Stylesheets
        Stylesheet { href: asset!("/assets/styles.css") }

        // Main layout with router - app-root fixes iOS Safari viewport issues
        div { class: "flex flex-col bg-bg overflow-hidden app-root",
            // Top bar with board selector (full width)
            BoardList {}
            // User profile bar with post input
            TopBar {}
            crate::components::system_notifications::SystemNotificationsBridge {}
            if *TEST_VIEW_MEMBER.read() {
                div { class: "flex-shrink-0 flex flex-wrap items-center justify-center gap-3 bg-sky-500/10 border-y border-sky-500/30 px-4 py-1 text-center text-xs text-sky-200",
                    span { "Member preview: owner and admin controls are hidden in this tab." }
                    button {
                        r#type: "button",
                        class: "underline hover:text-white",
                        onclick: move |_| *TEST_VIEW_MEMBER.write() = false,
                        "Exit preview"
                    }
                }
            }
            // Development warning, visible on every page including boards.
            div { class: "flex-shrink-0 bg-amber-500/10 border-y border-amber-500/30 px-4 py-1 text-center text-xs text-amber-200",
                "Work in progress: features and data can break without notice, there is no support. Avoid creating boards you plan to keep long term."
            }
            // Main content area (router)
            // The routed views use `flex-1` roots with their own scroll area.
            // Without a flex column here those roots have no bounded height and
            // the content is clipped by overflow-hidden instead of scrolling.
            div { class: "flex-1 min-h-0 overflow-hidden flex flex-col",
                Router::<Route> {}
            }
            toasts::ToastContainer {}
            crate::components::lightbox::Lightbox {}
            // Brand footer, centered under the board content. It opens the
            // About panel on every page, including the home page.
            div { class: "flex-shrink-0 px-4 py-2 border-t border-border bg-bg",
                button {
                    r#type: "button",
                    class: "mx-auto flex w-full max-w-md items-center gap-3 rounded-full border border-border bg-panel px-4 py-2 text-left hover:border-accent/60 hover:bg-surface transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60",
                    title: "About, build and backup",
                    aria_label: "About, build and backup",
                    onclick: move |_| *ABOUT_MODAL.write() = true,
                    img {
                        src: asset!("/assets/plaza_logo.svg"),
                        class: "w-7 h-7 flex-shrink-0",
                        alt: "",
                    }
                    div { class: "flex flex-1 flex-col leading-tight text-left",
                        span { class: "text-sm font-semibold text-text", "FreeTalk Plaza" }
                        span { class: "text-[10px] uppercase tracking-wide text-text-muted",
                            "About, build and backup"
                        }
                    }
                    span { class: "text-text-muted text-lg", "›" }
                }
            }
            EditBoardModal {}
            MemberInfoModal {}
            CreateBoardModal {}
            CategoryCreateModal {}
            AboutModal {}
            crate::components::device_drawer::DeviceDrawer {}
            crate::components::messages_view::MessagesModal {}
            DocumentTitleUpdater {}
        }
    }
}

/// Route component when no board is selected
#[component]
fn Home() -> Element {
    rsx! {
        div { class: "flex-1 flex flex-col items-center justify-center px-6 py-10 text-text-muted",
            div { class: "flex items-center gap-3",
                img {
                    src: asset!("/assets/plaza_logo.svg"),
                    class: "w-14 h-14 flex-shrink-0",
                    alt: "",
                }
                h1 { class: "text-3xl font-semibold text-text", "FreeTalk Plaza" }
            }
            p { class: "text-sm mt-1 mb-4", "Forums on Freenet" }
            p { class: "text-xl", "Select a board above or create one" }
            p { class: "text-sm mt-2", "Topics will appear here" }
        }
    }
}

/// Hidden developer route: enable the topic-contract layout for boards created
/// from this session. The shell bridges the hash into the app iframe, so this
/// works without changing the web container.
/// Test-only entry point: disables legacy delegate migration for this device
/// and offers the same reset as the board-not-found page.
#[component]
fn TestReset() -> Element {
    rsx! {
        div { class: "min-h-screen flex items-center justify-center p-6",
            button {
                r#type: "button",
                class: "px-4 py-2 border border-red-500/50 text-red-400 hover:bg-red-500/10 rounded-lg",
                onclick: move |_| {
                    #[cfg(target_arch = "wasm32")]
                    {
                        if let Some(window) = web_sys::window() {
                            if let Ok(Some(storage)) = window.local_storage() {
                                let _ = storage.set_item("plaza-skip-legacy", "1");
                            }
                        }
                    }
                    crate::util::reset::confirm_and_reset();
                },
                "Reset local data"
            }
        }
    }
}

#[component]
fn EnableSections() -> Element {
    let navigator = navigator();
    let mut done = use_signal(|| false);
    use_effect(move || {
        if *done.read() || !*BOARDS_LOADED.read() {
            return;
        }
        done.set(true);
        BOARDS.with_mut(|boards| {
            boards.client_features.topic_boards = true;
            boards.client_features.sectioned_boards = true;
        });
        info!("Section-sharded topic boards enabled from the developer route");
        navigator.push(Route::Home);
    });
    rsx! {
        div { class: "min-h-screen flex items-center justify-center p-6 text-text-muted",
            "Enabling section boards…"
        }
    }
}

#[component]
fn EnableTopics() -> Element {
    let navigator = navigator();
    let mut done = use_signal(|| false);
    use_effect(move || {
        if *done.read() || !*BOARDS_LOADED.read() {
            return;
        }
        done.set(true);
        BOARDS.with_mut(|boards| {
            boards.client_features.topic_boards = true;
        });
        info!("Topic-contract boards enabled from the developer route");
        navigator.push(Route::Home);
    });
    rsx! {
        div { class: "min-h-screen flex items-center justify-center p-6 text-text-muted",
            "Enabling topic boards…"
        }
    }
}

/// Reusable invite link screen.
#[component]
pub fn JoinBoard(token: String) -> Element {
    rsx! {
        crate::components::join_screen::JoinScreen { token }
    }
}

/// DM join link: register the conversation, verify the invite token and add
/// the local identity as a member.
#[component]
fn DmJoin(
    contract_id: String,
    token: String,
    key_version: String,
    key_b58: String,
) -> Element {
    let _ = (&contract_id, &token, &key_version, &key_b58);
    let mut started = use_signal(|| false);

    use_effect(move || {
        if *started.peek() {
            return;
        }
        started.set(true);
        let href = web_sys::window()
            .and_then(|window| window.location().href().ok())
            .unwrap_or_default();
        *DM_JOIN_PREFILL.write() = Some(href);
        *MESSAGES_OPEN.write() = true;
        navigator().replace(Route::Home);
    });

    rsx! {
        div { class: "flex-1 flex flex-col items-center justify-center px-6 py-10 text-text-muted",
            p { class: "text-sm", "Opening Messages…" }
        }
    }
}

/// Route component: open a public board in read-only mode, without joining.
#[component]
fn ViewOnly(board_id: String) -> Element {
    let mut problem = use_signal(|| None::<String>);
    let mut started = use_signal(|| false);
    let mut opened = use_signal(|| false);
    let effect_board_id = board_id.clone();

    use_effect(move || {
        if *started.peek() {
            return;
        }
        started.set(true);
        let board_id = effect_board_id.clone();
        let Ok(bytes) = bs58::decode(&board_id).into_vec() else {
            problem.set(Some("This board link is not valid.".to_string()));
            return;
        };
        let Ok(raw) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            problem.set(Some("This board link is not valid.".to_string()));
            return;
        };
        let Ok(owner_key) = ed25519_dalek::VerifyingKey::from_bytes(&raw) else {
            problem.set(Some("This board link is not valid.".to_string()));
            return;
        };
        match crate::util::spectator::open_spectator_board(owner_key) {
            // Stay on the /view route. Changing the hash made the app effect
            // race the route and fall back to Home before the board rendered.
            Ok(()) => opened.set(true),
            Err(error) => problem.set(Some(error)),
        }
    });

    rsx! {
        if let Some(error) = problem.read().as_ref() {
            div { class: "flex items-center justify-center min-h-screen p-6",
                p { class: "text-red-300", "{error}" }
            }
        } else if *opened.read() {
            BoardGate { board_id: board_id.clone(), PostsView {} }
        } else {
            div { class: "flex items-center justify-center min-h-screen p-6",
                p { class: "text-text-muted", "Opening the board in read-only mode..." }
            }
        }
    }
}

/// Route component for handling invitations
#[component]
fn Invite(invite_code: String) -> Element {    let invitation = use_memo(move || Invitation::from_encoded_string(&invite_code).ok());

    match invitation() {
        Some(inv) => rsx! {
            ReceiveInvitationModal { invitation: inv }
        },
        None => rsx! {
            div { class: "flex-1 flex flex-col items-center justify-center p-8 text-center",
                h1 { class: "text-2xl font-bold text-text mb-4", "Invalid Invitation" }
                p { class: "text-text-muted mb-6", "The invitation link appears to be invalid or corrupted." }
                button {
                    r#type: "button",
                    class: "px-4 py-2 bg-accent hover:bg-accent-hover text-white rounded-lg transition-colors inline-block",
                    onclick: move |_| {
                        if let Some(win) = web_sys::window() {
                            let _ = win.location().set_hash("/");
                        }
                    },
                    "Go to Home"
                }
            }
        },
    }
}

/// Guard for board routes - returns Some(Element) if board not found, None if OK
#[component]
fn BoardGate(board_id: String, children: Element) -> Element {
    let parsed = parse_board_key(&board_id);
    // Resolve the route id (which may be the current owner or the visible
    // profile) to the BOARDS map key after render.
    use_effect(move || {
        // Subscribe to the map explicitly: the route may be resolved before
        // the delegate load finishes, and the effect must run again once the
        // board data arrives.
        let _ = BOARDS.read().map.len();
        if let Some(key) = parsed {
            select_board(Some(key));
        }
    });

    // The route may name the founding board key, the current owner key or the
    // visible profile key. Check the route against the map directly as well as
    // CURRENT_BOARD so a selection made before the delegate load finishes does
    // not leave the gate on "Loading board…".
    let exists = use_memo(move || {
        let Some(route_key) = parsed else {
            return false;
        };
        let boards = BOARDS.read();
        if let Some(key) = CURRENT_BOARD.read().owner_key {
            if boards.map.contains_key(&key) {
                return true;
            }
        }
        boards.map.iter().any(|(map_key, board)| {
            *map_key == route_key
                || board.owner_vk == route_key
                || board.current_owner_key() == route_key
        })
    });
    let boards_loaded = *crate::components::app::BOARDS_LOADED.read();
    // A private board can be in the map with no usable key after a reload if
    // the active profile has no recipient blob. Showing the board would render
    // sealed content as empty; offer a way to switch profile instead.
    let key_missing = use_memo(move || {
        let Some(key) = CURRENT_BOARD.read().owner_key else {
            return false;
        };
        BOARDS.read()
            .map
            .get(&key)
            .is_some_and(|board| board.is_private() && board.get_secret().is_none())
    });

    if exists() {
        if key_missing() {
            return rsx! {
                div { class: "flex-1 flex flex-col items-center justify-center p-8 text-center",
                    p { class: "text-xl text-text-muted mb-2", "Board key missing" }
                    p { class: "text-text-muted mb-6 text-sm max-w-md",
                        "This private board is stored on this device, but the active profile cannot open it. Switch to a profile that joined this board, or ask a key holder to share the key."
                    }
                    div { class: "flex gap-2",
                        button {
                            r#type: "button",
                            class: "px-4 py-2 bg-accent hover:bg-accent/80 text-white rounded-lg",
                            onclick: move |_| {
                                *ABOUT_MODAL.write() = true;
                            },
                            "Open About"
                        }
                        button {
                            r#type: "button",
                            class: "px-4 py-2 bg-surface hover:bg-surface-hover text-text rounded-lg",
                            onclick: move |_| {
                                if let Some(window) = window() {
                                    let _ = window.location().set_hash("/");
                                }
                            },
                            "Go to Home"
                        }
                    }
                }
            };
        }
        return children;
    }

    rsx! {
        div { class: "flex-1 flex flex-col items-center justify-center p-8 text-center",
            if boards_loaded {
                p { class: "text-xl text-text-muted mb-2", "Board not found" }
                p { class: "text-text-muted mb-6 text-sm",
                    "This board is not stored on this device. If you were invited, open the invitation link again."
                }
            } else {
                p { class: "text-xl text-text-muted mb-2", "Loading board…" }
                p { class: "text-text-muted mb-6 text-sm",
                    "Waiting for the board state. It appears in the list above as soon as it is loaded."
                }

            }
            button {
                r#type: "button",
                class: "px-4 py-2 bg-accent hover:bg-accent/80 text-white rounded-lg transition-colors inline-block",
                onclick: move |_| {
                    if let Some(win) = web_sys::window() {
                        let _ = win.location().reload();
                    }
                },
                "Reload"
            }
            button {
                r#type: "button",
                class: "mt-2 px-4 py-2 bg-surface hover:bg-surface-hover text-text rounded-lg transition-colors inline-block",
                onclick: move |_| {
                    if let Some(win) = web_sys::window() {
                        let _ = win.location().set_hash("/");
                    }
                },
                "Go to Home"
            }
            button {
                r#type: "button",
                class: "mt-2 px-4 py-2 border border-red-500/50 text-red-400 hover:bg-red-500/10 rounded-lg transition-colors text-sm",
                onclick: move |_| crate::util::reset::confirm_and_reset(),
                "Reset local data"
            }
            p { class: "text-xs text-text-muted mt-3 max-w-md",
                "Clears the boards and image data stored on this device. The boards stay online; you need their identity token to come back."
            }
        }
    }
}

fn parse_board_key(board_id: &str) -> Option<VerifyingKey> {
    let bytes = bs58::decode(board_id).into_vec().ok()?;
    if bytes.len() != 32 {
        return None;
    }
    VerifyingKey::from_bytes(&bytes.try_into().ok()?).ok()
}
/// Route component for the board home
#[component]
fn Posts(board_id: String) -> Element {
    rsx! { BoardGate { board_id: board_id.clone(), BoardPosts { board_id } } }
}

/// Route component for a single post or topic.
#[component]
fn Post(board_id: String, post_id: String) -> Element {
    rsx! {
        BoardGate {
            board_id: board_id.clone(),
            BoardPost { board_id, post_id }
        }
    }
}

#[component]
fn Topic(board_id: String, topic_id: String) -> Element {
    rsx! {
        BoardGate {
            board_id: board_id.clone(),
            crate::components::topic_view::TopicView { board_id, topic_id }
        }
    }
}

/// The board home uses the topic index for new boards and the legacy message
/// view for old ones.
#[component]
fn BoardPosts(board_id: String) -> Element {
    let index_mode = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .and_then(|key| {
                BOARDS
                    .read()
                    .map
                    .get(&key)
                    .map(|board| board.board_state.mode.is_topic_index())
            })
            .unwrap_or(false)
    });
    if index_mode() {
        rsx! { crate::components::topic_index_view::TopicIndexView { board_id } }
    } else {
        rsx! { PostsView {} }
    }
}

#[component]
fn BoardPost(board_id: String, post_id: String) -> Element {
    let index_mode = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .and_then(|key| {
                BOARDS
                    .read()
                    .map
                    .get(&key)
                    .map(|board| board.board_state.mode.is_topic_index())
            })
            .unwrap_or(false)
    });
    if index_mode() {
        rsx! {
            crate::components::topic_view::TopicView {
                board_id,
                topic_id: post_id
            }
        }
    } else {
        rsx! { SinglePostView { post_id } }
    }
}

/// Route component for category view (uses PostsView with category_id)
#[component]
fn PostsInCategory(board_id: String, category_id: String) -> Element {
    let index_mode = use_memo(move || {
        CURRENT_BOARD
            .read()
            .owner_key
            .and_then(|key| {
                BOARDS
                    .read()
                    .map
                    .get(&key)
                    .map(|board| board.board_state.mode.is_topic_index())
            })
            .unwrap_or(false)
    });
    if index_mode() {
        rsx! { BoardGate { board_id: board_id.clone(), BoardPosts { board_id } } }
    } else {
        rsx! {
            BoardGate {
                board_id: board_id.clone(),
                PostsView { category_id: Some(category_id) }
            }
        }
    }
}

/// Route component for local search
#[component]
fn Search(board_id: String) -> Element {
    rsx! { BoardGate { board_id: board_id.clone(), SearchView {} } }
}

/// Route component for local notifications
#[component]
fn Notifications(board_id: String) -> Element {
    rsx! { BoardGate { board_id: board_id.clone(), NotificationsView {} } }
}

/// Route component for a member profile
#[component]
fn Profile(board_id: String, member_key: String) -> Element {
    rsx! {
        BoardGate {
            board_id: board_id.clone(),
            ProfileView { member_key: member_key.clone() }
        }
    }
}

/// Route component for conversation view
#[component]
fn ConversationView(board_id: String) -> Element {
    rsx! { BoardGate { board_id: board_id.clone(), Conversation {} } }
}

/// Route component for admin management view
#[component]
fn Admin(board_id: String) -> Element {
    rsx! {
        BoardGate { board_id: board_id.clone(), AdminView { tab: "admins".to_string() } }
    }
}

/// Admin view, banned users tab
#[component]
fn AdminBanned(board_id: String) -> Element {
    rsx! {
        BoardGate { board_id: board_id.clone(), AdminView { tab: "bans".to_string() } }
    }
}

/// Admin view, moderation queue tab
#[component]
fn AdminModeration(board_id: String) -> Element {
    rsx! {
        BoardGate { board_id: board_id.clone(), AdminView { tab: "moderation".to_string() } }
    }
}

/// Admin view, structure tab
#[component]
fn AdminStructure(board_id: String) -> Element {
    rsx! {
        BoardGate { board_id: board_id.clone(), AdminView { tab: "structure".to_string() } }
    }
}

/// Admin view, audit tab
#[component]
fn AdminAudit(board_id: String) -> Element {
    rsx! {
        BoardGate { board_id: board_id.clone(), AdminView { tab: "audit".to_string() } }
    }
}

/// Dedicated purge route
#[component]
fn AdminPurge(board_id: String, post_id: String) -> Element {
    rsx! {
        BoardGate { board_id: board_id.clone(),
            crate::components::purge_view::PurgeView { board_id: board_id.clone(), post_id: post_id.clone() }
        }
    }
}

/// Admin view, trash tab
#[component]
fn AdminTrash(board_id: String) -> Element {
    rsx! {
        BoardGate { board_id: board_id.clone(), AdminView { tab: "trash".to_string() } }
    }
}

/// Admin view, roles tab
#[component]
fn AdminRoles(board_id: String) -> Element {
    rsx! {
        BoardGate { board_id: board_id.clone(), AdminView { tab: "roles".to_string() } }
    }
}

/// Admin view, invite links tab
#[component]
fn AdminLinks(board_id: String) -> Element {
    rsx! {
        BoardGate { board_id: board_id.clone(), AdminView { tab: "links".to_string() } }
    }
}

/// Admin view, ownership tab
#[component]
fn AdminOwnership(board_id: String) -> Element {
    rsx! {
        BoardGate { board_id: board_id.clone(), AdminView { tab: "ownership".to_string() } }
    }
}

/// Route component for members view
#[component]
fn Members(board_id: String) -> Element {
    rsx! { BoardGate { board_id: board_id.clone(), MembersView {} } }
}

/// Route component for 404 not found
#[component]
fn NotFound(route: Vec<String>) -> Element {
    let path = format!("/{}", route.join("/"));
    rsx! {
        div { class: "flex-1 flex flex-col items-center justify-center p-8 text-center",
            h1 { class: "text-6xl font-bold text-text-muted mb-4", "404" }
            p { class: "text-xl text-text mb-2", "Page not found" }
            p { class: "text-text-muted mb-6", "The path \"{path}\" does not exist." }
            button {
                r#type: "button",
                class: "px-4 py-2 bg-accent hover:bg-accent-hover text-white rounded-lg transition-colors inline-block",
                onclick: move |_| {
                    if let Some(win) = web_sys::window() {
                        let _ = win.location().set_hash("/");
                    }
                },
                "Go to Home"
            }
        }
    }
}

/// Select a board by any known key and always store the BOARDS map key.
/// The URL, notifications, joins and the owner chain may name the founding
/// board key, the current owner key or the visible profile key; the map is
/// keyed by `BoardData.owner_vk` (the founding board key).
pub fn select_board(board_id: Option<VerifyingKey>) {
    let Some(vk) = board_id else {
        *CURRENT_BOARD.write() = CurrentBoard { owner_key: None };
        return;
    };
    // Resolve only identities that unambiguously name a board. A profile key
    // can be shared by several boards and resolving it arbitrarily caused
    // selection loops; the founding/current owner keys are unique.
    let resolved = BOARDS
        .read()
        .map
        .iter()
        .filter(|(map_key, board)| {
            **map_key == vk
                || board.owner_key().verifying_key() == vk
                || board.current_owner_key() == vk
                || board.owner_vk == vk
        })
        .map(|(map_key, _)| *map_key)
        .min_by(|a, b| a.as_bytes().cmp(b.as_bytes()))
        .unwrap_or(vk);
    if CURRENT_BOARD.read().owner_key != Some(resolved) {
        *CURRENT_BOARD.write() = CurrentBoard {
            owner_key: Some(resolved),
        };
        BOARDS.with_mut(|boards| {
            boards.current_board_key = Some(resolved);
        });
    }
    dm_delegate::ensure_identity_for_active_board();
}

/// Sync CURRENT_BOARD from URL board_id parameter
fn sync_board_from_url(board_id: &str) {
    // Parse board_id (base58-encoded VerifyingKey)
    if let Ok(bytes) = bs58::decode(board_id).into_vec() {
        if bytes.len() == 32 {
            if let Ok(vk) = VerifyingKey::from_bytes(&bytes.try_into().unwrap()) {
                select_board(Some(vk));
            }
        }
    }
}

/// `?topics=1` turns on the index-board path for boards created in this
/// session. The default stays the legacy message list until the topic UI has
/// full parity.
fn enable_topic_boards_from_query() {
    #[cfg(target_arch = "wasm32")]
    {
        let Some(window) = web_sys::window() else {
            return;
        };
        let Ok(search) = window.location().search() else {
            return;
        };
        if search.contains("topics=1") && !BOARDS.read().client_features.topic_boards {
            BOARDS.with_mut(|boards| boards.client_features.topic_boards = true);
            info!("Topic-contract boards enabled for new boards");
        }
        if search.contains("sections=1") && !BOARDS.read().client_features.sectioned_boards {
            BOARDS.with_mut(|boards| {
                boards.client_features.sectioned_boards = true;
                boards.client_features.topic_boards = true;
            });
            info!("Section-sharded topic boards enabled for new boards");
        }
    }
}

#[cfg(not(feature = "example-data"))]
fn initial_boards() -> Boards {
    Boards {
        map: std::collections::HashMap::new(),
        current_board_key: None,
        profiles: Vec::new(),
        removed: Vec::new(),
        board_order: Vec::new(),
        archived: Vec::new(),
        client_features: crate::board_data::ClientFeatures::default(),
        migrated_boards: Vec::new(),
        blocked_image_hashes: Vec::new(),
        auto_renew_images: false,
        last_auto_renew_at: 0,
        owned_images: Vec::new(),
    }
}

#[cfg(feature = "example-data")]
fn initial_boards() -> Boards {
    crate::example_data::create_example_boards()
}

pub struct EditBoardModalSignal {
    pub board: Option<VerifyingKey>,
}

pub struct CreateBoardModalSignal {
    pub show: bool,
}

pub struct MemberInfoModalSignal {
    pub member: Option<MemberId>,
}

/// Gets the authorization token from the window global variable.
/// The Freenet HTTP gateway injects this token into the HTML as:
/// <script>window.__FREENET_AUTH_TOKEN__ = "token_value";</script>
fn get_auth_token_from_window() {
    if let Some(win) = window() {
        match js_sys::Reflect::get(&win, &"__FREENET_AUTH_TOKEN__".into()) {
            Ok(token_value) => {
                if let Some(token) = token_value.as_string() {
                    info!("Found auth token from window global");
                    *AUTH_TOKEN.write() = Some(token);
                } else if token_value.is_undefined() || token_value.is_null() {
                    debug!("Auth token not injected by gateway (running locally?)");
                } else {
                    debug!("Auth token has unexpected type");
                }
            }
            Err(err) => {
                error!("Failed to read auth token from window: {:?}", err);
            }
        }
    }
}


