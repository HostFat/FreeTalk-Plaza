//! Deterministic rate limits.
//!
//! The contract has no clock: a limit based on "now" would make the same
//! update valid on one peer and invalid on another. The limits therefore use
//! the signed timestamps already in the records and are evaluated as a
//! property of the state: no member may hold more than `limit` records inside
//! any `window_ms` span. A burst that would break that property is rejected,
//! so every peer agrees on the result and the state stays verifiable.

use crate::board_state::member::MemberId;

pub const DEFAULT_RATE_WINDOW_MS: u64 = 60_000;
pub const DEFAULT_MAX_POSTS_PER_WINDOW: u32 = 120;
pub const DEFAULT_MAX_BANS_PER_WINDOW: u32 = 10;

/// Topic creation is capped per author: each entry grows the board index that
/// every member downloads on every update.
pub const TOPIC_RATE_WINDOW_MS: i64 = 60 * 60 * 1000;
pub const MAX_TOPICS_PER_WINDOW: usize = 30;

/// Reports are signed board records too; cap them per reporter.
pub const REPORT_RATE_WINDOW_MS: i64 = 60 * 60 * 1000;
pub const MAX_REPORTS_PER_WINDOW: usize = 60;

/// Milliseconds since the epoch for a signed timestamp. Times before the
/// epoch clamp to 0; the value only orders records from the same signer.
pub fn system_time_ms(time: std::time::SystemTime) -> i64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

/// Inverse of [`system_time_ms`]; negative values clamp to the epoch.
pub fn system_time_from_ms(ms: i64) -> std::time::SystemTime {
    if ms <= 0 {
        std::time::SystemTime::UNIX_EPOCH
    } else {
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms as u64)
    }
}

/// Whether `times` contains more than `limit` records inside a window of
/// `window_ms`. The window is half-open: `[t, t + window_ms)`.
pub fn exceeds_window(times: &[i64], window_ms: i64, limit: usize) -> bool {
    if limit == 0 || times.len() <= limit {
        return false;
    }
    let mut sorted = times.to_vec();
    sorted.sort_unstable();
    let mut start = 0;
    for end in 0..sorted.len() {
        while sorted[end] - sorted[start] >= window_ms {
            start += 1;
        }
        if end - start + 1 > limit {
            return true;
        }
    }
    false
}

/// The first member whose records break the window limit, if any.
pub fn exceeding_member(
    records: impl Iterator<Item = (MemberId, i64)>,
    window_ms: i64,
    limit: usize,
) -> Option<MemberId> {
    if limit == 0 {
        return None;
    }
    let mut by_member: std::collections::HashMap<MemberId, Vec<i64>> =
        std::collections::HashMap::new();
    for (member, time) in records {
        by_member.entry(member).or_default().push(time);
    }
    by_member
        .into_iter()
        .find(|(_, times)| exceeds_window(times, window_ms, limit))
        .map(|(member, _)| member)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(byte: u8) -> MemberId {
        MemberId::from_bytes([byte; 32])
    }

    #[test]
    fn a_window_is_half_open() {
        // [0, 1000) holds three records; the one at 1000 starts a new window.
        assert!(!exceeds_window(&[0, 500, 999, 1000], 1000, 3));
        assert!(exceeds_window(&[0, 500, 999, 1000], 1000, 2));
    }

    #[test]
    fn unsorted_and_duplicate_times_are_handled() {
        assert!(exceeds_window(&[500, 0, 100, 200], 1000, 3));
        assert!(!exceeds_window(&[0, 0, 0], 1000, 3));
    }

    #[test]
    fn limits_are_per_member() {
        let records = vec![
            (member(1), 0),
            (member(1), 10),
            (member(2), 0),
            (member(2), 10),
            (member(2), 20),
        ];
        assert_eq!(exceeding_member(records.into_iter(), 1000, 2), Some(member(2)));
    }

    #[test]
    fn zero_disables_the_limit() {
        assert!(!exceeds_window(&[0, 1, 2, 3], 1, 0));
    }
}
