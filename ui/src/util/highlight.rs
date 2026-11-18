//! Small syntax highlighter for fenced code blocks.
//!
//! It covers the languages that appear in the forum most often and stays
//! deliberately simple: keywords, strings, comments, numbers and a few
//! identifier shapes. Anything it does not know is left as plain text, so a
//! new language degrades to an uncoloured block instead of breaking.

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Keyword,
    String,
    Comment,
    Number,
    Function,
    Type,
    Punct,
    Text,
}

fn keywords(lang: &str) -> Option<&'static [&'static str]> {
    let lang = lang
        .trim()
        .trim_start_matches("language-")
        .to_ascii_lowercase();
    let list: &'static [&'static str] = match lang.as_str() {
        "rust" | "rs" => &[
            "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum",
            "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
            "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super",
            "trait", "true", "type", "unsafe", "use", "where", "while", "Box", "Vec", "Option",
            "Result", "Some", "None", "Ok", "Err",
        ],
        "javascript" | "js" | "jsx" | "typescript" | "ts" | "tsx" => &[
            "const", "let", "var", "function", "return", "if", "else", "for", "while", "do",
            "switch", "case", "break", "continue", "class", "extends", "new", "this", "super",
            "import", "export", "from", "default", "async", "await", "try", "catch", "finally",
            "throw", "typeof", "instanceof", "in", "of", "null", "undefined", "true", "false",
            "interface", "type", "enum", "implements", "public", "private", "protected",
            "readonly", "static", "as", "satisfies",
        ],
        "python" | "py" => &[
            "def", "class", "return", "if", "elif", "else", "for", "while", "in", "not", "and",
            "or", "is", "None", "True", "False", "import", "from", "as", "try", "except",
            "finally", "raise", "with", "lambda", "pass", "break", "continue", "yield", "async",
            "await", "global", "nonlocal", "assert", "del",
        ],
        "shell" | "sh" | "bash" | "zsh" => &[
            "if", "then", "else", "elif", "fi", "for", "in", "do", "done", "case", "esac",
            "while", "until", "function", "return", "export", "local", "readonly",
        ],
        "json" => &["true", "false", "null"],
        _ => return None,
    };
    Some(list)
}

fn comment_start(lang: &str) -> &'static str {
    let lang = lang
        .trim()
        .trim_start_matches("language-")
        .to_ascii_lowercase();
    match lang.as_str() {
        "python" | "py" | "shell" | "sh" | "bash" | "zsh" => "#",
        _ => "//",
    }
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn span(kind: Kind, text: &str, out: &mut String) {
    let class = match kind {
        Kind::Keyword => Some("tok-keyword"),
        Kind::String => Some("tok-string"),
        Kind::Comment => Some("tok-comment"),
        Kind::Number => Some("tok-number"),
        Kind::Function => Some("tok-function"),
        Kind::Type => Some("tok-type"),
        Kind::Punct => Some("tok-punct"),
        Kind::Text => None,
    };
    match class {
        Some(class) => {
            out.push_str("<span class=\"");
            out.push_str(class);
            out.push_str("\">");
            out.push_str(&escape(text));
            out.push_str("</span>");
        }
        None => out.push_str(&escape(text)),
    }
}

/// Highlight `code` when the language is known; `None` leaves the block plain.
pub fn highlight_html(lang: &str, code: &str) -> Option<String> {
    let words = keywords(lang)?;
    let comment = comment_start(lang);
    let lang_name = lang
        .trim()
        .trim_start_matches("language-")
        .to_ascii_lowercase();
    let json = lang_name == "json";
    let bytes = code.as_bytes();
    let mut out = String::with_capacity(code.len() + code.len() / 2);
    let mut index = 0usize;
    let mut plain = String::new();

    let flush = |plain: &mut String, out: &mut String| {
        if !plain.is_empty() {
            span(Kind::Text, plain, out);
            plain.clear();
        }
    };

    while index < bytes.len() {
        let ch = code[index..].chars().next().unwrap();
        let rest = &code[index..];

        if rest.starts_with(comment) {
            let end = rest.find('\n').map(|offset| index + offset).unwrap_or(code.len());
            flush(&mut plain, &mut out);
            span(Kind::Comment, &code[index..end], &mut out);
            index = end;
            continue;
        }

        if ch == '"' || ch == '\'' || (ch == '`' && !json) {
            let quote = ch;
            let mut end = index + ch.len_utf8();
            let mut escaped = false;
            let mut closed = false;
            for next in code[end..].chars() {
                end += next.len_utf8();
                if escaped {
                    escaped = false;
                    continue;
                }
                if next == '\\' && quote != '`' {
                    escaped = true;
                    continue;
                }
                if next == quote {
                    closed = true;
                    break;
                }
                if next == '\n' && quote != '`' {
                    break;
                }
            }
            if closed || quote == '`' {
                flush(&mut plain, &mut out);
                span(Kind::String, &code[index..end], &mut out);
                index = end;
                continue;
            }
        }

        if ch.is_ascii_digit() {
            let mut end = index + 1;
            while end < bytes.len() {
                let next = code[end..].chars().next().unwrap();
                if next.is_ascii_alphanumeric() || next == '_' || next == '.' {
                    end += next.len_utf8();
                } else {
                    break;
                }
            }
            flush(&mut plain, &mut out);
            span(Kind::Number, &code[index..end], &mut out);
            index = end;
            continue;
        }

        if ch.is_alphanumeric() || ch == '_' {
            let mut end = index + ch.len_utf8();
            while end < bytes.len() {
                let next = code[end..].chars().next().unwrap();
                if next.is_alphanumeric() || next == '_' {
                    end += next.len_utf8();
                } else {
                    break;
                }
            }
            let word = &code[index..end];
            let after = code[end..].trim_start();
            let kind = if words.contains(&word) {
                Kind::Keyword
            } else if after.starts_with('(') {
                Kind::Function
            } else if word.chars().next().is_some_and(|first| first.is_uppercase()) {
                Kind::Type
            } else {
                Kind::Text
            };
            if kind == Kind::Text {
                plain.push_str(word);
            } else {
                flush(&mut plain, &mut out);
                span(kind, word, &mut out);
            }
            index = end;
            continue;
        }

        if "{}()[]<>;:,.!+-*/%=&|^~?@#$".contains(ch) {
            flush(&mut plain, &mut out);
            span(Kind::Punct, &ch.to_string(), &mut out);
            index += ch.len_utf8();
            continue;
        }

        plain.push(ch);
        index += ch.len_utf8();
    }
    flush(&mut plain, &mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_keywords_and_comments_are_marked() {
        let html = highlight_html("rust", "let x = 1; // note\nfn main() {}").unwrap();
        assert!(html.contains("tok-keyword\">let</span>"), "{html}");
        assert!(html.contains("tok-number\">1</span>"), "{html}");
        assert!(html.contains("tok-comment\">// note</span>"), "{html}");
        assert!(html.contains("tok-function\">main</span>"), "{html}");
    }

    #[test]
    fn strings_are_escaped_and_marked() {
        let html = highlight_html("javascript", "const x = \"<b>\";").unwrap();
        assert!(html.contains("tok-string\">&quot;&lt;b&gt;&quot;</span>"), "{html}");
    }

    #[test]
    fn unknown_language_stays_plain() {
        assert!(highlight_html("brainfuck", "+++").is_none());
    }

    #[test]
    fn python_uses_hash_comments() {
        let html = highlight_html("python", "x = 1  # note\ndef f(): pass").unwrap();
        assert!(html.contains("tok-comment\"># note</span>"), "{html}");
        assert!(html.contains("tok-keyword\">def</span>"), "{html}");
    }
}
