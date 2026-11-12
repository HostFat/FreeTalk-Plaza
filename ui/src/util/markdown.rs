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

    // Add target="_blank" and rel="noopener noreferrer" to all links
    make_links_open_in_new_tab(&html)
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
}
