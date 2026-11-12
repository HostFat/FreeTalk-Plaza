pub mod chat_delegate;
pub mod document_title;
pub mod freenet_api;
pub mod notifications;
pub mod receive_times;
pub mod sync_info;

use super::{
    admin_view::AdminView, board_list::BoardList, conversation::Conversation,
    members::MembersView, top_bar::TopBar,
};
use crate::board_data::{Boards, CurrentBoard};
use crate::components::app::document_title::DocumentTitleUpdater;
use crate::components::app::freenet_api::freenet_synchronizer::SynchronizerMessage;
use crate::components::app::freenet_api::freenet_synchronizer::SynchronizerStatus;
use crate::components::app::freenet_api::FreenetSynchronizer;
use crate::components::about_modal::AboutModal;
use crate::components::board_list::create_board_modal::CreateBoardModal;
use crate::components::board_list::edit_board_modal::EditBoardModal;
use crate::components::board_list::receive_invitation_modal::ReceiveInvitationModal;
use crate::components::category_create_modal::CategoryCreateModal;
use crate::components::members::member_info_modal::MemberInfoModal;
use crate::components::members::Invitation;
use crate::components::posts_view::{PostsView, SinglePostView};
use crate::invites::PendingInvites;
use dioxus::document::{Link, Stylesheet};
use dioxus::logger::tracing::{debug, error, info};
use dioxus::prelude::*;
use ed25519_dalek::VerifyingKey;
use freenet_stdlib::client_api::WebApi;
use plaza_core::board_state::member::MemberId;
use plaza_core::board_state::message::MessageId;
use std::str::FromStr;

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
    #[route("/board/:board_id")]
    Posts { board_id: String },
    #[route("/board/:board_id/post/:post_id")]
    Post { board_id: String, post_id: String },
    #[route("/board/:board_id/category/:category_id")]
    PostsInCategory { board_id: String, category_id: String },
    #[route("/board/:board_id/conversation")]
    ConversationView { board_id: String },
    #[route("/board/:board_id/admin")]
    Admin { board_id: String },
    #[route("/board/:board_id/members")]
    Members { board_id: String },
    #[route("/:..route")]
    NotFound { route: Vec<String> },
}

pub static BOARDS: GlobalSignal<Boards> = Global::new(initial_boards);

/// Set once the boards stored in the delegate have been read (or the delegate
/// answered that it has none). Until then `BOARDS` is empty only because the
/// load has not finished, and persisting it would overwrite real data.
pub static BOARDS_LOADED: GlobalSignal<bool> = Global::new(|| false);

/// True when the delegate we loaded from actually contained boards. Used to
/// refuse writing an empty map over real data if a load ever fails validation.
pub static DELEGATE_HAD_BOARDS: GlobalSignal<bool> = Global::new(|| false);

/// Board states fetched from the network without a local identity, shown
/// read-only. Keyed by the board's owner key.
pub static READ_ONLY_BOARDS: GlobalSignal<
    std::collections::HashMap<VerifyingKey, plaza_core::ChatBoardStateV1>,
> = Global::new(std::collections::HashMap::new);

/// Read-only fetches in flight.
pub static READ_ONLY_FETCHES: GlobalSignal<std::collections::HashSet<VerifyingKey>> =
    Global::new(std::collections::HashSet::new);
pub static CURRENT_BOARD: GlobalSignal<CurrentBoard> =
    Global::new(|| CurrentBoard { owner_key: None });
pub static MEMBER_INFO_MODAL: GlobalSignal<MemberInfoModalSignal> =
    Global::new(|| MemberInfoModalSignal { member: None });
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
pub static WEB_API: GlobalSignal<Option<WebApi>> = Global::new(|| None);
pub static AUTH_TOKEN: GlobalSignal<Option<String>> = Global::new(|| None);

// Tracks which boards need to be synced due to USER actions (not network updates)
// This prevents infinite loops where network responses trigger more syncs
pub static NEEDS_SYNC: GlobalSignal<std::collections::HashSet<VerifyingKey>> =
    Global::new(std::collections::HashSet::new);

/// Tracks the current category being viewed (for auto-parenting new posts/categories)
pub static CURRENT_CATEGORY: GlobalSignal<CurrentCategoryContext> =
    Global::new(|| CurrentCategoryContext::default());

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

/// Mark a board as needing sync, deferred via setTimeout(0).
///
/// IMPORTANT: Writing to NEEDS_SYNC triggers a Dioxus use_effect synchronously,
/// which cascades into ProcessBoards → BOARDS.read() and other signal reads.
/// If called while any signal is borrowed, this causes a RefCell re-entrant
/// borrow panic in WASM (especially on Firefox mobile).
///
/// Uses crate::util::defer() to break out of the WASM call stack entirely,
/// ensuring the write happens in a completely clean execution context.
pub fn mark_needs_sync(board_key: ed25519_dalek::VerifyingKey) {
    crate::util::defer(move || {
        NEEDS_SYNC.write().insert(board_key);
    });
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

    // Watch CURRENT_BOARD and navigate if URL doesn't match
    // This handles the case where sync/delegate sets the current board but URL remains unchanged
    use_effect(move || {
        let current_board = CURRENT_BOARD.read();
        if let Some(owner_key) = current_board.owner_key {
            let board_id = bs58::encode(owner_key.as_bytes()).into_string();

            // Check if URL already shows this board to avoid race conditions with regular navigation
            let url_matches = if let Some(window) = window() {
                if let Ok(hash) = window.location().hash() {
                    // URL hash is like "#/board/{board_id}" or "#/board/{board_id}/..."
                    hash.contains(&format!("/board/{}", board_id))
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
        Stylesheet { href: asset!("/assets/main.css") }

        // Main layout with router - app-root fixes iOS Safari viewport issues
        div { class: "flex flex-col bg-bg overflow-hidden app-root",
            // Top bar with board selector (full width)
            BoardList {}
            // User profile bar with post input
            TopBar {}
            // Main content area (router)
            div { class: "flex-1 min-h-0 overflow-hidden",
                Router::<Route> {}
            }
            EditBoardModal {}
            MemberInfoModal {}
            CreateBoardModal {}
            CategoryCreateModal {}
            AboutModal {}
            DocumentTitleUpdater {}
        }
    }
}

/// Route component when no board is selected
#[component]
fn Home() -> Element {
    rsx! {
        div { class: "flex-1 flex flex-col items-center justify-center h-64 text-text-muted",
            h1 { class: "text-3xl font-semibold text-text", "FreeTalk Plaza" }
            p { class: "text-sm mt-1 mb-4", "A forum on Freenet" }
            p { class: "text-xl", "Select a board above or create one" }
            p { class: "text-sm mt-2", "Posts will appear here" }
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

/// Route component for handling invitations
#[component]
fn Invite(invite_code: String) -> Element {
    let invitation = use_memo(move || Invitation::from_encoded_string(&invite_code).ok());

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
fn board_guard(board_id: &str) -> Option<Element> {
    // Parse and sync the board
    sync_board_from_url(board_id);

    // Check if the board exists in our map
    let board_exists = parse_board_key(board_id)
        .map(|vk| BOARDS.read().map.contains_key(&vk))
        .unwrap_or(false);

    if board_exists {
        None
    } else {
        // On a page reload the route is known before the delegate load finishes,
        // so the board is briefly missing. Show a loading state and let
        // WaitingForBoard re-enter the route once the board arrives, instead of
        // a dead-end error.
        Some(rsx! {
            WaitingForBoard { board_id: board_id.to_string() }
        })
    }
}

fn parse_board_key(board_id: &str) -> Option<VerifyingKey> {
    let bytes = bs58::decode(board_id).into_vec().ok()?;
    if bytes.len() != 32 {
        return None;
    }
    VerifyingKey::from_bytes(&bytes.try_into().ok()?).ok()
}

/// Shown while the board referenced by the URL is not in memory yet.
///
/// It watches BOARDS and re-enters the current route when the board appears,
/// which re-runs the guard. Without this, a reload left the guard's error on
/// screen even after the delegate had loaded the board.
#[component]
fn WaitingForBoard(board_id: String) -> Element {
    let parsed = parse_board_key(&board_id);
    let ready = use_memo(move || {
        parsed
            .map(|key| BOARDS.read().map.contains_key(&key))
            .unwrap_or(false)
    });
    // Once the delegate load is done, a missing board is genuinely unknown.
    let boards_loaded = *crate::components::app::BOARDS_LOADED.read();
    let read_only_state = use_memo(move || {
        parsed.and_then(|key| crate::components::app::READ_ONLY_BOARDS.read().get(&key).cloned())
    });
    let mut requested = use_signal(|| false);

    use_effect(move || {
        if *ready.read() {
            let path = web_sys::window()
                .and_then(|w| w.location().hash().ok())
                .unwrap_or_default();
            let path = path.trim_start_matches('#');
            if let Ok(route) = Route::from_str(path) {
                navigator().replace(route);
            }
        }
    });

    if let Some(state) = read_only_state.read().clone() {
        return rsx! {
            ReadOnlyBoardView { board_id: board_id.clone(), state: state }
        };
    }

    rsx! {
        div { class: "flex-1 flex flex-col items-center justify-center p-8 text-center",
            if boards_loaded {
                p { class: "text-xl text-text-muted mb-2", "Board not found" }
                p { class: "text-text-muted mb-6 text-sm",
                    "This board is not stored on this device. You can open it read-only, or open the invitation link again if you have one."
                }
            } else {
                p { class: "text-xl text-text-muted mb-2", "Loading board…" }
                p { class: "text-text-muted mb-6 text-sm",
                    "Waiting for the board state. It appears in the list above as soon as it is loaded."
                }
            }
            div { class: "flex items-center gap-3",
                button {
                    r#type: "button",
                    class: "px-4 py-2 bg-surface hover:bg-surface-hover text-text rounded-lg transition-colors inline-block",
                    onclick: move |_| {
                        if let Some(win) = web_sys::window() {
                            let _ = win.location().set_hash("/");
                        }
                    },
                    "Go to Home"
                }
                if boards_loaded {
                    button {
                        r#type: "button",
                        class: "px-4 py-2 bg-accent hover:bg-accent-hover text-white rounded-lg transition-colors inline-block disabled:opacity-50",
                        disabled: *requested.read(),
                        onclick: move |_| {
                            if let Some(key) = parsed {
                                requested.set(true);
                                let _ = SYNCHRONIZER
                                    .write()
                                    .get_message_sender()
                                    .unbounded_send(SynchronizerMessage::FetchBoardForRead {
                                        owner_vk: key,
                                    });
                            }
                        },
                        if *requested.read() { "Fetching…" } else { "Open read-only" }
                    }
                }
            }
        }
    }
}

/// Read-only rendering of a board fetched from the network.
#[component]
fn ReadOnlyBoardView(board_id: String, state: plaza_core::ChatBoardStateV1) -> Element {
    fn nickname(state: &plaza_core::ChatBoardStateV1, id: MemberId) -> String {
        state
            .member_info
            .member_info
            .iter()
            .find(|info| info.member_info.member_id == id)
            .map(|info| info.member_info.preferred_nickname.to_string_lossy())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| format!("{id}"))
    }

    let mut categories: Vec<String> = Vec::new();
    let mut posts: Vec<(String, String)> = Vec::new();
    for message in &state.recent_messages.messages {
        let body = &message.message.content;
        if body.is_category() {
            if let Some(decoded) = body.decode_content() {
                categories.push(decoded.to_display_string());
            }
        } else if !body.is_action() {
            posts.push((
                nickname(&state, message.message.author),
                body.to_string_lossy(),
            ));
        }
    }
    posts.sort_by(|a, b| a.0.cmp(&b.0));
    let short_id: String = board_id.chars().take(8).collect();

    rsx! {
        div { class: "flex-1 flex flex-col overflow-y-auto",
            div { class: "bg-amber-500/10 border-b border-amber-500/30 px-6 py-3 text-sm text-amber-200",
                "Read-only view: this board is not stored on this device, so you cannot post here."
            }
            div { class: "px-6 py-5",
                h1 { class: "text-2xl font-semibold text-text mb-1", "Board {short_id}…" }
                p { class: "text-text-muted text-sm mb-4",
                    "{state.members.members.len()} members · {posts.len()} posts · {categories.len()} categories"
                }

                if !categories.is_empty() {
                    div { class: "mb-5",
                        h2 { class: "text-sm uppercase tracking-wide text-text-muted mb-2", "Categories" }
                        div { class: "flex flex-wrap gap-2",
                            for category in categories.iter() {
                                span {
                                    class: "px-3 py-1 bg-surface rounded-full text-sm text-text",
                                    "{category}"
                                }
                            }
                        }
                    }
                }

                if posts.is_empty() {
                    p { class: "text-text-muted", "No posts on this board." }
                } else {
                    div { class: "space-y-2",
                        for (author, text) in posts.iter() {
                            div { class: "bg-surface rounded-lg p-3",
                                p { class: "text-text-muted text-xs mb-1", "{author}" }
                                p { class: "text-text text-sm whitespace-pre-wrap", "{text}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Route component for posts list view
#[component]
fn Posts(board_id: String) -> Element {
    if let Some(guard) = board_guard(&board_id) {
        return guard;
    }
    rsx! { PostsView {} }
}

/// Route component for single post view
#[component]
fn Post(board_id: String, post_id: String) -> Element {
    if let Some(guard) = board_guard(&board_id) {
        return guard;
    }
    rsx! { SinglePostView { post_id: post_id } }
}

/// Route component for category view (uses PostsView with category_id)
#[component]
fn PostsInCategory(board_id: String, category_id: String) -> Element {
    if let Some(guard) = board_guard(&board_id) {
        return guard;
    }
    rsx! { PostsView { category_id: Some(category_id) } }
}

/// Route component for conversation view
#[component]
fn ConversationView(board_id: String) -> Element {
    if let Some(guard) = board_guard(&board_id) {
        return guard;
    }
    rsx! { Conversation {} }
}

/// Route component for admin management view
#[component]
fn Admin(board_id: String) -> Element {
    if let Some(guard) = board_guard(&board_id) {
        return guard;
    }
    rsx! { AdminView {} }
}

/// Route component for members view
#[component]
fn Members(board_id: String) -> Element {
    if let Some(guard) = board_guard(&board_id) {
        return guard;
    }
    rsx! { MembersView {} }
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

/// Sync CURRENT_BOARD from URL board_id parameter
fn sync_board_from_url(board_id: &str) {
    // Parse board_id (base58-encoded VerifyingKey)
    if let Ok(bytes) = bs58::decode(board_id).into_vec() {
        if bytes.len() == 32 {
            if let Ok(vk) = VerifyingKey::from_bytes(&bytes.try_into().unwrap()) {
                // Only update if different to avoid infinite loops
                let current = CURRENT_BOARD.read().owner_key;
                if current != Some(vk) {
                    debug!("Syncing CURRENT_BOARD from URL: {}", board_id);
                    *CURRENT_BOARD.write() = CurrentBoard {
                        owner_key: Some(vk),
                    };
                }
            }
        }
    }
}

#[cfg(not(feature = "example-data"))]
fn initial_boards() -> Boards {
    Boards {
        map: std::collections::HashMap::new(),
        current_board_key: None,
        migrated_boards: Vec::new(),
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
