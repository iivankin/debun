pub(super) fn collect_metadata(strings: &str) -> Vec<(String, String)> {
    let mut metadata = Vec::new();
    for key in [
        "PACKAGE_NAME",
        "PACKAGE_URL",
        "VERSION",
        "BUILD_TIME",
        "README_URL",
        "REPOSITORY_URL",
        "HOMEPAGE_URL",
        "API_URL",
        "BASE_API_URL",
    ] {
        if let Some(value) = find_best_quoted_value(strings, key) {
            metadata.push((key.to_string(), value));
        }
    }
    metadata.sort();
    metadata.dedup();
    metadata
}

fn find_best_quoted_value(haystack: &str, key: &str) -> Option<String> {
    let needle = format!("{key}:");
    let mut best: Option<(usize, String)> = None;
    let mut search_from = 0usize;

    while let Some(relative_start) = haystack[search_from..].find(&needle) {
        let start = search_from + relative_start + needle.len();
        let Some(value) = find_next_quoted_literal(&haystack[start..]) else {
            search_from = start;
            continue;
        };
        let score = metadata_value_score(key, &value);
        if score > 0 {
            let should_replace = best.as_ref().is_none_or(|(best_score, best_value)| {
                score > *best_score || (score == *best_score && value.len() < best_value.len())
            });
            if should_replace {
                best = Some((score, value));
            }
        }
        search_from = start;
    }

    best.map(|(_, value)| value)
}

fn find_next_quoted_literal(haystack: &str) -> Option<String> {
    let quote_offset = haystack
        .char_indices()
        .find(|(_, ch)| *ch == '"' || *ch == '\'')?
        .0;
    let quote = haystack[quote_offset..].chars().next()?;
    let value_start = quote_offset + quote.len_utf8();
    let rest = haystack.get(value_start..)?;
    let value_end = rest.find(quote)?;
    Some(rest[..value_end].to_string())
}

fn metadata_value_score(key: &str, value: &str) -> usize {
    match key {
        "PACKAGE_NAME" => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                0
            } else if trimmed.len() <= 64 && trimmed.chars().all(|ch| !ch.is_control()) {
                10
            } else {
                1
            }
        }
        "VERSION" => {
            if let Some((major, minor, patch)) = parse_semver(value) {
                1_000_000_000usize
                    .saturating_add(major.saturating_mul(1_000_000))
                    .saturating_add(minor.saturating_mul(1_000))
                    .saturating_add(patch)
            } else if value.chars().any(|ch| ch.is_ascii_digit()) {
                2
            } else {
                1
            }
        }
        "BUILD_TIME" => {
            if value.contains('T') && value.ends_with('Z') && value.contains('-') {
                5
            } else if value.chars().any(|ch| ch.is_ascii_digit()) {
                2
            } else {
                1
            }
        }
        key if key.ends_with("_URL") || key.ends_with("_URI") => {
            let mut score = 0usize;
            if value.starts_with("https://") {
                score += 50;
            } else if value.starts_with("http://") {
                score += 10;
            }
            if value.contains("localhost") || value.contains("127.0.0.1") {
                score = score.saturating_sub(40);
            }
            if value.contains("github.com") {
                score += 10;
            }
            if value.contains("/docs") || value.contains("/readme") {
                score += 10;
            }
            if score > 0 { score } else { 1 }
        }
        _ => 1,
    }
}

fn parse_semver(value: &str) -> Option<(usize, usize, usize)> {
    let trimmed = value.split(['-', '+']).next().unwrap_or(value).trim();
    let mut parts = trimmed.split('.');
    let major = parts.next();
    let minor = parts.next();
    let patch = parts.next();
    let extra = parts.next();
    match (major, minor, patch, extra) {
        (Some(major), Some(minor), Some(patch), None)
            if major.chars().all(|ch| ch.is_ascii_digit())
                && minor.chars().all(|ch| ch.is_ascii_digit())
                && patch.chars().all(|ch| ch.is_ascii_digit()) =>
        {
            Some((
                major.parse().ok()?,
                minor.parse().ok()?,
                patch.parse().ok()?,
            ))
        }
        _ => None,
    }
}
