//! One place for action feedback: a toast on success, a red toast on error.

use crate::components::app::toasts;
use std::future::Future;

/// Report the outcome of a local state change. Returns the value on success.
pub fn submit<T>(result: Result<T, String>, label: &str) -> Option<T> {
    match result {
        Ok(value) => {
            toasts::show(format!("{label}. Syncing with the network…"));
            Some(value)
        }
        Err(error) => {
            toasts::show_error(format!("{label}: {error}"));
            None
        }
    }
}

/// Report the outcome of an async action without blocking the caller.
pub fn spawn_submit<F>(future: F, label: &'static str)
where
    F: Future<Output = Result<(), String>> + 'static,
{
    crate::util::safe_spawn_local(async move {
        match future.await {
            Ok(()) => toasts::show(format!("{label}. Syncing with the network…")),
            Err(error) => toasts::show_error(format!("{label}: {error}")),
        }
    });
}
