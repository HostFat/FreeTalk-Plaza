//! Crop rectangle math, kept separate so it can be tested off the browser.

/// Turn a drag between two points, expressed as percentages of the rendered
/// image, into `(left, top, width, height)` percentages. `ratio` locks the
/// pixel aspect ratio when greater than zero.
pub fn drag_rect(
    start: (f64, f64),
    current: (f64, f64),
    render: (f64, f64),
    ratio: f64,
    natural: (u32, u32),
) -> (f64, f64, f64, f64) {
    if render.0 <= 0.0 || render.1 <= 0.0 {
        return (0.0, 0.0, 100.0, 100.0);
    }
    let x = (current.0 / render.0 * 100.0).clamp(0.0, 100.0);
    let y = (current.1 / render.1 * 100.0).clamp(0.0, 100.0);
    let left = start.0.clamp(0.0, 100.0).min(x);
    let top = start.1.clamp(0.0, 100.0).min(y);
    let mut width = (x - start.0).abs().max(1.0);
    let mut height = (y - start.1).abs().max(1.0);
    if ratio > 0.0 && natural.0 > 0 && natural.1 > 0 {
        height = width * natural.0 as f64 / (ratio * natural.1 as f64);
        if top + height > 100.0 {
            height = 100.0 - top;
            width = height * ratio * natural.1 as f64 / natural.0 as f64;
        }
    }
    (
        left,
        top,
        width.min(100.0 - left).max(1.0),
        height.min(100.0 - top).max(1.0),
    )
}

#[cfg(test)]
mod tests {
    use super::drag_rect;

    #[test]
    fn a_free_drag_maps_to_percentages() {
        let (left, top, width, height) =
            drag_rect((20.0, 20.0), (60.0, 50.0), (100.0, 100.0), 0.0, (200, 100));
        assert!((left - 20.0).abs() < 0.01);
        assert!((top - 20.0).abs() < 0.01);
        assert!((width - 40.0).abs() < 0.01);
        assert!((height - 30.0).abs() < 0.01);
    }

    #[test]
    fn a_locked_ratio_sets_the_height_from_the_width() {
        // 200x100 source, square lock: a 40% width is 80 px, so 80 px tall,
        // which is 80% of the rendered height.
        let (_, _, width, height) =
            drag_rect((10.0, 10.0), (50.0, 12.0), (100.0, 100.0), 1.0, (200, 100));
        assert!((width - 40.0).abs() < 0.01);
        assert!((height - 80.0).abs() < 0.01);
    }

    #[test]
    fn the_rect_stays_inside_the_image() {
        let (left, top, width, height) =
            drag_rect((10.0, 10.0), (90.0, 90.0), (100.0, 100.0), 1.0, (100, 100));
        assert!(left + width <= 100.0 + 0.01);
        assert!(top + height <= 100.0 + 0.01);
        assert!(width >= 1.0 && height >= 1.0);
    }

    #[test]
    fn a_zero_render_size_falls_back_to_the_whole_image() {
        assert_eq!(
            drag_rect((10.0, 10.0), (50.0, 50.0), (0.0, 0.0), 0.0, (10, 10)),
            (0.0, 0.0, 100.0, 100.0)
        );
    }
}
