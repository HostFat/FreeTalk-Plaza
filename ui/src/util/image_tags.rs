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
///
/// Tags inside inline code and fenced code blocks stay text: a post that
/// shows `[img=1]` as an example must not lose it to an image.
pub fn parse(text: &str) -> Vec<Segment> {
    let chars: Vec<char> = text.chars().collect();
    let mut segments = Vec::new();
    let mut text_start = 0;
    let mut i = 0;
    let mut fence: Option<(char, usize)> = None;

    while i < chars.len() {
        if i == 0 || chars[i - 1] == '\n' {
            let line_end = chars[i..]
                .iter()
                .position(|c| *c == '\n')
                .map(|offset| i + offset)
                .unwrap_or(chars.len());
            let line: String = chars[i..line_end].iter().collect();
            if let Some((ch, len)) = fence_marker(line.trim_start()) {
                match fence {
                    Some((open_ch, open_len)) if open_ch == ch && len >= open_len => {
                        fence = None;
                    }
                    None => fence = Some((ch, len)),
                    _ => {}
                }
                i = if line_end < chars.len() {
                    line_end + 1
                } else {
                    chars.len()
                };
                continue;
            }
            if fence.is_some() {
                i = if line_end < chars.len() {
                    line_end + 1
                } else {
                    chars.len()
                };
                continue;
            }
        }

        if fence.is_some() {
            i += 1;
            continue;
        }

        if chars[i] == '`' {
            let run = run_len(&chars, i, '`');
            if let Some(close) = find_run(&chars, i + run, '`', run) {
                i = close + run;
                continue;
            }
            i += run;
            continue;
        }

        if chars[i] == '[' && starts_with(&chars, i, "[img=") {
            if let Some(end) = chars[i..].iter().position(|c| *c == ']').map(|p| i + p) {
                let body: String = chars[i + 5..end].iter().collect();
                if let Some((index, align)) = parse_body(&body) {
                    if i > text_start {
                        segments.push(Segment::Text(chars[text_start..i].iter().collect()));
                    }
                    segments.push(Segment::Image { index, align });
                    i = end + 1;
                    text_start = i;
                    continue;
                }
            }
        }
        i += 1;
    }

    if text_start < chars.len() {
        segments.push(Segment::Text(chars[text_start..].iter().collect()));
    }
    segments
}

/// A fenced code block marker: at least three backticks or tildes.
fn fence_marker(line: &str) -> Option<(char, usize)> {
    let ch = line.chars().next()?;
    if ch != '`' && ch != '~' {
        return None;
    }
    let len = line.chars().take_while(|c| *c == ch).count();
    if len >= 3 {
        Some((ch, len))
    } else {
        None
    }
}

fn starts_with(chars: &[char], start: usize, prefix: &str) -> bool {
    prefix
        .chars()
        .enumerate()
        .all(|(offset, expected)| chars.get(start + offset) == Some(&expected))
}

fn run_len(chars: &[char], start: usize, ch: char) -> usize {
    chars[start..].iter().take_while(|c| **c == ch).count()
}

fn find_run(chars: &[char], from: usize, ch: char, len: usize) -> Option<usize> {
    let mut i = from;
    while i < chars.len() {
        if chars[i] == ch {
            let run = run_len(chars, i, ch);
            if run == len {
                return Some(i);
            }
            i += run;
        } else {
            i += 1;
        }
    }
    None
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

    #[test]
    fn tags_in_code_stay_text() {
        let text = "`[img=1]` and\n```\n[img=2]\n```\n[img=3]";
        let images: Vec<_> = parse(text)
            .into_iter()
            .filter(|segment| matches!(segment, Segment::Image { .. }))
            .collect();
        assert_eq!(
            images,
            vec![Segment::Image {
                index: 2,
                align: ImageAlign::Center
            }]
        );
        assert_eq!(strip(text), "`[img=1]` and\n```\n[img=2]\n```");
    }

    #[test]
    fn double_backticks_protect_their_span() {
        let text = "``[img=1]`` [img=2]";
        let images: Vec<_> = parse(text)
            .into_iter()
            .filter(|segment| matches!(segment, Segment::Image { .. }))
            .collect();
        assert_eq!(
            images,
            vec![Segment::Image {
                index: 1,
                align: ImageAlign::Center
            }]
        );
    }

    #[test]
    fn tilde_fences_are_code_too() {
        let text = "~~~\n[img=1]\n~~~\n[img=2]";
        let count = parse(text)
            .iter()
            .filter(|segment| matches!(segment, Segment::Image { .. }))
            .count();
        assert_eq!(count, 1);
    }
}
