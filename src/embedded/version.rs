use super::raw::{printable_strings, version_scan_regions};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Semver {
    major: u64,
    minor: u64,
    patch: u64,
}

#[derive(Debug, Clone)]
struct VersionCandidate {
    version: Semver,
    score: usize,
}

pub(super) fn detect_bun_version(bytes: &[u8]) -> Option<String> {
    let mut best: Option<VersionCandidate> = None;
    for region in version_scan_regions(bytes) {
        update_best_candidate(&printable_strings(region), &mut best);
    }

    best.map(format_candidate)
}

fn update_best_candidate(strings: &str, best: &mut Option<VersionCandidate>) {
    for line in strings.lines() {
        let Some(candidate) = detect_candidate(line) else {
            continue;
        };
        let should_replace = best
            .as_ref()
            .map(|best| {
                candidate.score > best.score
                    || (candidate.score == best.score && candidate.version > best.version)
            })
            .unwrap_or(true);
        if should_replace {
            *best = Some(candidate);
        }
    }
}

fn detect_candidate(line: &str) -> Option<VersionCandidate> {
    // These markers come from Bun's own upstream sources:
    // - `bun <cmd> v...` banners in `src/cli/*`
    // - `Bun v...` crash/runtime banners in `src/Global.zig`
    // Prefer lines that also include Bun's short git SHA in parentheses.
    let (version, score) = if let Some(rest) = line.strip_prefix("Bun v") {
        let version = parse_version_prefix(rest)?;
        let mut score = 80;
        if has_short_git_sha(rest) {
            score += 40;
        }
        if line.contains("macOS") || line.contains("Linux") || line.contains("Windows") {
            score += 10;
        }
        (version, score)
    } else if let Some(version) = parse_cli_banner_version(line) {
        let mut score = 100;
        if has_short_git_sha(line) {
            score += 40;
        }
        (version, score)
    } else if let Some((_, rest)) = line.split_once("bun-v") {
        (parse_version_prefix(rest)?, 30)
    } else {
        return None;
    };

    Some(VersionCandidate { version, score })
}

fn format_candidate(candidate: VersionCandidate) -> String {
    format!(
        "bun-v{}.{}.{}",
        candidate.version.major, candidate.version.minor, candidate.version.patch
    )
}

fn parse_cli_banner_version(line: &str) -> Option<Semver> {
    let rest = line.strip_prefix("bun ")?;
    let version_start = rest.find(" v")?;
    parse_version_prefix(rest.get(version_start + 2..)?)
}

fn parse_version_prefix(input: &str) -> Option<Semver> {
    let version_len = input
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
        .count();
    if version_len == 0 {
        return None;
    }

    parse_semver(input.get(..version_len)?)
}

fn parse_semver(value: &str) -> Option<Semver> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }

    Some(Semver {
        major,
        minor,
        patch,
    })
}

fn has_short_git_sha(line: &str) -> bool {
    let Some(start) = line.find('(') else {
        return false;
    };
    let Some(end) = line[start + 1..].find(')') else {
        return false;
    };
    let candidate = &line[start + 1..start + 1 + end];
    (7..=8).contains(&candidate.len()) && candidate.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::detect_bun_version;

    #[test]
    fn prefers_cli_banner_with_short_sha() {
        let strings = "\
random app text\n\
bun build v1.3.10 (30e609e0)\n\
Please pass a complete version number to --target=bun-v1.3.10\n";

        assert_eq!(
            detect_bun_version(strings.as_bytes()).as_deref(),
            Some("bun-v1.3.10")
        );
    }

    #[test]
    fn detects_bun_version_from_runtime_banner() {
        let strings = "\
some other text\n\
Bun v1.3.5 (1e86cebd) macOS Silicon\n";

        assert_eq!(
            detect_bun_version(strings.as_bytes()).as_deref(),
            Some("bun-v1.3.5")
        );
    }
}
