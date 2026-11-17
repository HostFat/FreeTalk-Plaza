//! Shared retry timing.

/// Delay before the next spectator fetch. A cold contract can take minutes to
/// route, so back off instead of giving up after a few tries.
pub fn spectator_delay_ms(attempt: u32) -> f64 {
    match attempt {
        0 => 5_000.0,
        1 => 10_000.0,
        2 => 20_000.0,
        3 => 30_000.0,
        _ => 60_000.0,
    }
}

#[cfg(test)]
mod tests {
    use super::spectator_delay_ms;

    #[test]
    fn the_spectator_backoff_grows_and_caps() {
        assert_eq!(spectator_delay_ms(0), 5_000.0);
        assert_eq!(spectator_delay_ms(1), 10_000.0);
        assert_eq!(spectator_delay_ms(2), 20_000.0);
        assert_eq!(spectator_delay_ms(3), 30_000.0);
        assert_eq!(spectator_delay_ms(4), 60_000.0);
        assert_eq!(spectator_delay_ms(19), 60_000.0);
    }
}
