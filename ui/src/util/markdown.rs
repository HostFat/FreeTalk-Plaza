/// Utilities for converting text to HTML with markdown and URL linkification.

/// Convert message text to HTML with clickable links that open in new tabs.
///
/// Uses GFM autolink literals to linkify plain URLs while correctly
/// skipping URLs inside code spans and other non-text contexts.
pub fn text_to_html(text: &str) -> String {
    // Convert single newlines to hard breaks (two spaces + newline)
    // This preserves line breaks in chat messages as users expect
    let with_hard_breaks = text.replace("\n", "  \n");

    // Be explicit about the two safety switches rather than relying on the
    // library defaults: raw HTML is escaped and dangerous URL protocols are
    // dropped. Both are off in markdown-rs today, and a silent default change
    // must not turn user content into markup.
    let mut options = markdown::Options::gfm();
    options.compile.allow_dangerous_html = false;
    options.compile.allow_dangerous_protocol = false;

    let html = markdown::to_html_with_options(&with_hard_breaks, &options)
        .unwrap_or_else(|_| markdown::to_html(&with_hard_breaks));

    // A message is not a document: a `#` heading must not out-rank the page
    // headings, so cap what the content can produce.
    let html = clamp_headings(&html);

    // Block automatic image loads from Markdown (`![alt](url)`) so remote URLs
    // cannot leak the reader's IP address or track reads. Convert http(s) URLs
    // into ordinary clickable links; drop all other image tags to plain text.
    let html = rewrite_markdown_images(&html);

    // Colour fenced code blocks whose language is known.
    let html = highlight_code_blocks(&html);

    // Add target="_blank" and rel="noopener noreferrer" to all links
    make_links_open_in_new_tab(&html)
}

fn unescape_html(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// Post-process markdown's `<pre><code class="language-x">` blocks. The code
/// text is escaped by markdown; the highlighter receives the plain form and
/// escapes it again in its own spans.
fn highlight_code_blocks(html: &str) -> String {
    const CLOSE: &str = "</code></pre>";
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(start) = rest.find("<pre><code") {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        // Close on the `<code ...>` tag, not on the `<pre>` tag.
        let Some(code_tag) = after.find("<code") else {
            out.push_str(after);
            return out;
        };
        let Some(open_end) = after[code_tag..].find('>').map(|offset| code_tag + offset) else {
            out.push_str(after);
            return out;
        };
        let open = &after[..=open_end];
        let Some(close) = after.find(CLOSE) else {
            out.push_str(after);
            return out;
        };
        let inner = &after[open_end + 1..close];
        let lang = open
            .split("language-")
            .nth(1)
            .and_then(|tail| {
                tail.split(|ch: char| ch == '"' || ch == ' ' || ch == '>')
                    .next()
            })
            .unwrap_or("");
        out.push_str(&open.replacen("<pre>", "<pre class=\"code-block\">", 1));
        if let Some(highlighted) = crate::util::highlight::highlight_html(lang, &unescape_html(inner))
        {
            out.push_str(&highlighted);
        } else {
            out.push_str(inner);
        }
        out.push_str(CLOSE);
        rest = &after[close + CLOSE.len()..];
    }
    out.push_str(rest);
    out
}

/// Cap heading levels in rendered content: h1/h2/h3 become h3, h4-h6 become h4.
///
/// Escaped markup inside code spans is `&lt;h1&gt;`, so it is not touched.
fn clamp_headings(html: &str) -> String {
    let mut out = html.to_string();
    for (from, to) in [("h1", "h3"), ("h2", "h3"), ("h5", "h4"), ("h6", "h4")] {
        out = out.replace(&format!("<{from}>"), &format!("<{to}>"));
        out = out.replace(&format!("</{from}>"), &format!("</{to}>"));
    }
    out
}

/// Replace every `<img ...>` tag emitted by Markdown with either a safe
/// clickable link (for `http://`/`https://` URLs) or plain text (for any other
/// scheme/empty src) so no automatic network request can leak the user's IP.
fn rewrite_markdown_images(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(start) = rest.find("<img ") {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        let Some(end) = after.find('>') else {
            out.push_str(after);
            return out;
        };
        let tag = &after[..=end];
        let src = extract_html_attr(tag, "src").unwrap_or("");
        let alt = extract_html_attr(tag, "alt").unwrap_or("");
        let is_http = src.starts_with("https://") || src.starts_with("http://");
        if is_http {
            let label = if alt.is_empty() { src } else { alt };
            out.push_str("<a href=\"");
            out.push_str(src);
            out.push_str("\">[Image: ");
            out.push_str(label);
            out.push_str("]</a>");
        } else if !alt.is_empty() {
            out.push_str("[Image: ");
            out.push_str(alt);
            out.push(']');
        } else {
            out.push_str("[Image]");
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn extract_html_attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let idx = tag.find(&needle)?;
    let value_start = idx + needle.len();
    let tail = &tag[value_start..];
    let value_end = tail.find('"')?;
    Some(&tail[..value_end])
}

/// Add target="_blank" and rel="noopener noreferrer" to all anchor tags in HTML.
pub fn make_links_open_in_new_tab(html: &str) -> String {
    html.replace(
        "<a href=\"",
        "<a target=\"_blank\" rel=\"noopener noreferrer\" href=\"",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_url_is_linkified() {
        let html = text_to_html("check out https://freenet.org for more info");
        assert!(
            html.contains(
                r#"<a target="_blank" rel="noopener noreferrer" href="https://freenet.org">"#
            ),
            "bare URL should be linkified with target=_blank: {html}"
        );
    }

    #[test]
    fn url_in_code_span_not_linkified() {
        let html = text_to_html("did you do `curl -fsSL https://freenet.org/install.sh | sh`?");
        assert!(
            !html.contains("<a "),
            "URL inside backticks should NOT be linkified: {html}"
        );
    }

    #[test]
    fn url_in_fenced_code_block_not_linkified() {
        let html = text_to_html("```\ncurl https://freenet.org/install.sh\n```");
        assert!(
            !html.contains("<a "),
            "URL in code block should NOT be linkified: {html}"
        );
    }

    #[test]
    fn fenced_code_gets_syntax_classes() {
        let html = text_to_html("```rust\nlet x = 1; // note\n```");
        assert!(html.contains("code-block"), "{html}");
        assert!(html.contains("tok-keyword"), "{html}");
        assert!(html.contains("tok-comment"), "{html}");
    }

    #[test]
    fn unknown_fence_stays_plain_code() {
        let html = text_to_html("```brainfuck\n+++\n```");
        assert!(html.contains("<code"), "{html}");
        assert!(!html.contains("tok-"), "{html}");
    }

    #[test]
    fn markdown_link_preserved() {
        let html = text_to_html("see [Freenet](https://freenet.org)");
        assert!(
            html.contains(r#"href="https://freenet.org">"#),
            "markdown link should be preserved: {html}"
        );
        assert!(
            html.contains(">Freenet</a>"),
            "markdown link text should be preserved: {html}"
        );
    }

    #[test]
    fn newlines_become_hard_breaks() {
        let html = text_to_html("line one\nline two");
        assert!(
            html.contains("<br"),
            "newlines should become hard breaks: {html}"
        );
    }

    #[test]
    fn raw_html_is_escaped() {
        let html = text_to_html("<script>alert(1)</script>");
        assert!(
            !html.contains("<script>"),
            "raw HTML must not survive as markup: {html}"
        );
        assert!(
            html.contains("&lt;script&gt;"),
            "raw HTML should appear as text: {html}"
        );
    }

    #[test]
    fn dangerous_protocols_are_dropped() {
        let html = text_to_html("[click](javascript:alert(1))");
        assert!(
            !html.contains("javascript:alert"),
            "javascript: URLs must not reach an href: {html}"
        );
    }

    #[test]
    fn headings_are_capped() {
        let h1 = text_to_html("# Big title");
        assert!(h1.contains("<h3>"), "h1 should render as h3: {h1}");
        assert!(!h1.contains("<h1>"), "h1 must not appear: {h1}");

        let h5 = text_to_html("##### Small title");
        assert!(h5.contains("<h4>"), "h5 should render as h4: {h5}");
        assert!(!h5.contains("<h5>"), "h5 must not appear: {h5}");
    }

    #[test]
    fn heading_text_in_code_is_not_rewritten() {
        let html = text_to_html("`<h1>`");
        assert!(
            html.contains("&lt;h1&gt;"),
            "escaped heading markup stays literal: {html}"
        );
    }

    #[test]
    fn external_markdown_images_never_emit_img_tags() {
        let html = text_to_html("![tracker](https://attacker.example/pixel.png)");
        assert!(
            !html.contains("<img"),
            "external Markdown images must never emit <img> tags: {html}"
        );
        assert!(
            html.contains(
                r#"<a target="_blank" rel="noopener noreferrer" href="https://attacker.example/pixel.png">[Image: tracker]</a>"#
            ),
            "http(s) Markdown images should degrade to safe links: {html}"
        );
    }

    #[test]
    fn non_http_markdown_images_become_plain_text() {
        let html = text_to_html("![x](data:image/svg+xml,<svg/>)");
        assert!(
            !html.contains("<img"),
            "non-http Markdown images must not emit <img> tags: {html}"
        );
        assert!(
            !html.contains("data:image"),
            "data: URI must not leak into href or img: {html}"
        );
    }
}
