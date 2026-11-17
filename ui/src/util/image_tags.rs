//! Inline image tags, in the style of classic forums: `[img=1]` places the
//! first attachment at that point, `[img=2 left]` also sets the alignment.

use plaza_core::board_state::images::ImageAlign;
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq)]
pub enum Segment {
    Text(String),
    Image { index: usize, align: ImageAlign },
}

/// Split a message body into text and image placeholders. Indexes are
/// zero-based here and become one-based in the tag.
pub fn parse(text: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("[img=") {
        if start > 0 {
            segments.push(Segment::Text(rest[..start].to_string()));
        }
        let after = &rest[start + 5..];
        let Some(end) = after.find(']') else {
            segments.push(Segment::Text(rest[start..].to_string()));
            return segments;
        };
        let body = &after[..end];
        match parse_body(body) {
            Some((index, align)) => segments.push(Segment::Image { index, align }),
            None => segments.push(Segment::Text(rest[start..start + 5 + end + 1].to_string())),
        }
        rest = &after[end + 1..];
    }
    if !rest.is_empty() {
        segments.push(Segment::Text(rest.to_string()));
    }
    segments
}

fn parse_body(body: &str) -> Option<(usize, ImageAlign)> {
    let mut parts = body.split_whitespace();
    let number: usize = parts.next()?.parse().ok()?;
    if number == 0 {
        return None;
    }
    let align = match parts.next() {
        None => ImageAlign::Center,
        Some("left") => ImageAlign::Left,
        Some("center") => ImageAlign::Center,
        Some("right") => ImageAlign::Right,
        Some(_) => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((number - 1, align))
}

/// One-based indexes referenced by the tags.
pub fn tagged_indices(text: &str) -> HashSet<usize> {
    parse(text)
        .into_iter()
        .filter_map(|segment| match segment {
            Segment::Image { index, .. } => Some(index),
            Segment::Text(_) => None,
        })
        .collect()
}

/// Remove the tags, for previews and lists.
pub fn strip(text: &str) -> String {
    parse(text)
        .into_iter()
        .map(|segment| match segment {
            Segment::Text(value) => value,
            Segment::Image { .. } => String::new(),
        })
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{parse, strip, tagged_indices, Segment};
    use plaza_core::board_state::images::ImageAlign;

    #[test]
    fn plain_text_has_no_segments() {
        assert_eq!(parse("hello"), vec![Segment::Text("hello".to_string())]);
    }

    #[test]
    fn a_tag_becomes_an_image_segment() {
        assert_eq!(
            parse("before [img=1] after"),
            vec![
                Segment::Text("before ".to_string()),
                Segment::Image {
                    index: 0,
                    align: ImageAlign::Center
                },
                Segment::Text(" after".to_string()),
            ]
        );
    }

    #[test]
    fn an_alignment_is_read() {
        assert_eq!(
            parse("[img=2 right]"),
            vec![Segment::Image {
                index: 1,
                align: ImageAlign::Right
            }]
        );
    }

    #[test]
    fn malformed_tags_stay_text() {
        let text = "[img=0] [img=x] [img=1 sideways]";
        assert!(parse(text).iter().all(|segment| matches!(segment, Segment::Text(_))));
        assert_eq!(strip(text), text);
    }

    #[test]
    fn tagged_indices_and_strip() {
        let text = "a [img=1] b [img=3 left] c";
        assert_eq!(tagged_indices(text), [0, 2].into_iter().collect());
        assert_eq!(strip(text), "a  b  c");
    }
}
