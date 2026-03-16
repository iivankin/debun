use std::{error::Error, fs, path::Path};

const BUN_JS_MARKER: &[u8] = b"// @bun";

#[derive(Debug, Clone)]
pub struct ExtractedSource {
    pub source: String,
    pub trimmed_prefix: usize,
    pub trimmed_suffix: usize,
    pub had_nul_terminator: bool,
}

impl ExtractedSource {
    pub fn from_path(path: &Path) -> Result<Self, Box<dyn Error>> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_source(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            trimmed_prefix: 0,
            trimmed_suffix: 0,
            had_nul_terminator: false,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        if let Ok(text) = std::str::from_utf8(bytes) {
            return Ok(Self::from_text(text));
        }

        let Some((start, end)) = find_best_slice(bytes, BUN_JS_MARKER) else {
            return Err("input is not UTF-8 and no Bun JS marker was found".into());
        };
        let source = String::from_utf8(bytes[start..end].to_vec())?;

        Ok(Self {
            source,
            trimmed_prefix: start,
            trimmed_suffix: bytes.len().saturating_sub(end),
            had_nul_terminator: end < bytes.len(),
        })
    }

    fn from_text(text: &str) -> Self {
        let (start, end) =
            find_best_slice(text.as_bytes(), BUN_JS_MARKER).unwrap_or((0, text.len()));
        let nul_offset = if end < text.len() {
            Some(end - start)
        } else {
            None
        };
        let source = text[start..end].to_string();

        Self {
            source,
            trimmed_prefix: start,
            trimmed_suffix: text.len().saturating_sub(end),
            had_nul_terminator: nul_offset.is_some(),
        }
    }
}

fn find_best_slice(haystack: &[u8], needle: &[u8]) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    let mut search_from = 0;

    while let Some(relative_start) = haystack[search_from..]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        let start = search_from + relative_start;
        let end = haystack[start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| start + offset)
            .unwrap_or(haystack.len());

        let is_better = best
            .map(|(best_start, best_end)| {
                end.saturating_sub(start) > best_end.saturating_sub(best_start)
            })
            .unwrap_or(true);

        if is_better {
            best = Some((start, end));
        }

        search_from = start + needle.len();
    }

    best
}
