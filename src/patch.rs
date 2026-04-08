use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use crate::{
    args::{ApplyPatchConfig, PatchConfig, defaults},
    embedded::{EmbeddedFile, EmbeddedKind, inspect_binary},
    pack_support::{
        base_executable_path, read_original_input_path, resign_if_needed,
        resolve_replacements_root, resolve_workspace_root,
    },
    standalone::{
        OptionalReplacement, ReplacementCounts, ReplacementParts, RequiredReplacement,
        StandaloneModule, StandaloneSidecarKind, inspect_executable, repack_executable,
    },
};

const PATCH_MAGIC: &str = "debun-patch/v1";

pub(crate) struct PatchSummary {
    pub(crate) replacements_root: PathBuf,
    pub(crate) record_counts: ReplacementCounts,
}

pub(crate) struct ApplyPatchSummary {
    pub(crate) input_file: PathBuf,
    pub(crate) out_file: PathBuf,
    pub(crate) record_counts: ReplacementCounts,
}

#[derive(Debug, Clone)]
struct PatchBundle {
    original_path: Option<String>,
    records: Vec<PatchRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PatchRecord {
    module_path: String,
    part: PatchPartKind,
    expected: PatchBytes,
    replacement: PatchBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum PatchPartKind {
    Contents,
    SourceMap,
    Bytecode,
    ModuleInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PatchBytes {
    Absent,
    Present(Vec<u8>),
}

impl PatchPartKind {
    const ALL: [Self; 4] = [
        Self::Contents,
        Self::SourceMap,
        Self::Bytecode,
        Self::ModuleInfo,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Contents => "contents",
            Self::SourceMap => "sourcemap",
            Self::Bytecode => "bytecode",
            Self::ModuleInfo => "module-info",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "contents" => Some(Self::Contents),
            "sourcemap" => Some(Self::SourceMap),
            "bytecode" => Some(Self::Bytecode),
            "module-info" => Some(Self::ModuleInfo),
            _ => None,
        }
    }

    fn workspace_virtual_path(self, module: &StandaloneModule) -> String {
        match self {
            Self::Contents => module.virtual_path.clone(),
            Self::SourceMap => module.sidecar_path(StandaloneSidecarKind::SourceMapBinary),
            Self::Bytecode => module.sidecar_path(StandaloneSidecarKind::BytecodeBinary),
            Self::ModuleInfo => module.sidecar_path(StandaloneSidecarKind::ModuleInfoBinary),
        }
    }

    fn workspace_relative_path(self, module: &StandaloneModule) -> String {
        self.workspace_virtual_path(module)
            .trim_start_matches('/')
            .to_string()
    }

    fn expected_state(self, module: &StandaloneModule) -> PatchBytes {
        match self {
            Self::Contents => PatchBytes::Present(module.bytes.clone()),
            Self::SourceMap => PatchBytes::from_optional(module.sourcemap.clone()),
            Self::Bytecode => PatchBytes::from_optional(module.bytecode.clone()),
            Self::ModuleInfo => PatchBytes::from_optional(module.module_info.clone()),
        }
    }

    fn count(self, counts: &mut ReplacementCounts) {
        match self {
            Self::Contents => counts.contents += 1,
            Self::SourceMap => counts.sourcemaps += 1,
            Self::Bytecode => counts.bytecodes += 1,
            Self::ModuleInfo => counts.module_infos += 1,
        }
    }
}

impl PatchBytes {
    fn from_optional(value: Option<Vec<u8>>) -> Self {
        value.map_or(Self::Absent, Self::Present)
    }

    const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    fn render(&self) -> String {
        match self {
            Self::Absent => "absent".to_string(),
            Self::Present(bytes) => format!("present:{}", hex_encode(bytes)),
        }
    }

    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        if value == "absent" {
            return Ok(Self::Absent);
        }

        let hex = value
            .strip_prefix("present:")
            .ok_or_else(|| format!("invalid patch state: {value}"))?;
        Ok(Self::Present(hex_decode(hex)?))
    }
}

impl PatchBundle {
    fn counts(&self) -> ReplacementCounts {
        let mut counts = ReplacementCounts::default();
        for record in &self.records {
            record.part.count(&mut counts);
        }
        counts
    }
}

pub fn create_patch(config: &PatchConfig) -> Result<PatchSummary, Box<dyn Error>> {
    let workspace_root = resolve_workspace_root(&config.from_dir)?;
    let replacements_root = resolve_replacements_root(&workspace_root)?;
    let base_executable = base_executable_path(&workspace_root);
    let original_bytes = fs::read(&base_executable)?;
    let standalone = inspect_executable(&original_bytes)?
        .ok_or("patch only supports Bun standalone executables")?;
    let base_inspection = inspect_binary(&base_executable)?
        .ok_or("patch only supports Bun standalone executables")?;
    let extracted_paths = base_inspection
        .files
        .iter()
        .map(|file| file.virtual_path.as_str())
        .collect::<HashSet<_>>();

    validate_workspace_files(
        &replacements_root,
        standalone.bunfs_modules(),
        &base_inspection.files,
    )?;

    let mut records = Vec::new();
    let mut counts = ReplacementCounts::default();

    for module in standalone.bunfs_modules() {
        for part in PatchPartKind::ALL {
            let expected = part.expected_state(module);
            let replacement = read_workspace_state(
                &replacements_root,
                module,
                part,
                extracted_paths.contains(part.workspace_virtual_path(module).as_str()),
            )?;
            let Some(replacement) = replacement else {
                continue;
            };
            if expected == replacement {
                continue;
            }
            if part == PatchPartKind::Contents && replacement.is_absent() {
                return Err(format!(
                    "workspace file {} is missing; contents patches cannot delete BunFS modules",
                    part.workspace_virtual_path(module)
                )
                .into());
            }

            part.count(&mut counts);
            records.push(PatchRecord {
                module_path: module.virtual_path.clone(),
                part,
                expected,
                replacement,
            });
        }
    }

    records.sort_by(|left, right| {
        left.module_path
            .cmp(&right.module_path)
            .then(left.part.cmp(&right.part))
    });

    let bundle = PatchBundle {
        original_path: read_original_input_path(&workspace_root)
            .map(|path| path.display().to_string()),
        records,
    };

    if let Some(parent) = config
        .out_file
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(&config.out_file, render_patch_bundle(&bundle))?;

    Ok(PatchSummary {
        replacements_root,
        record_counts: counts,
    })
}

pub fn apply_patch(config: &ApplyPatchConfig) -> Result<ApplyPatchSummary, Box<dyn Error>> {
    let bundle = parse_patch_bundle(&fs::read(&config.patch_file)?)?;
    let input_file = resolve_apply_input(config, &bundle)?;
    let out_file = config
        .out_file
        .clone()
        .unwrap_or_else(|| defaults::default_apply_patch_out_file(&input_file));
    let original_bytes = fs::read(&input_file)?;
    let original_permissions = fs::metadata(&input_file)?.permissions();
    let standalone = inspect_executable(&original_bytes)?
        .ok_or("apply-patch only supports Bun standalone executables")?;
    let replacements = build_replacements(&bundle, standalone.bunfs_modules())?;
    let record_counts = bundle.counts();
    let output_bytes = if replacements.is_empty() {
        original_bytes
    } else {
        repack_executable(&original_bytes, standalone, &replacements)?.bytes
    };

    if let Some(parent) = out_file
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(&out_file, output_bytes)?;
    fs::set_permissions(&out_file, original_permissions)?;
    resign_if_needed(&out_file)?;

    Ok(ApplyPatchSummary {
        input_file,
        out_file,
        record_counts,
    })
}

fn resolve_apply_input(
    config: &ApplyPatchConfig,
    bundle: &PatchBundle,
) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(input) = &config.input {
        return Ok(input.clone());
    }

    bundle.original_path.as_deref().map(PathBuf::from).ok_or(
        "apply-patch requires an input binary or a patch file with original-path metadata".into(),
    )
}

fn build_replacements<'a>(
    bundle: &PatchBundle,
    modules: impl IntoIterator<Item = &'a StandaloneModule>,
) -> Result<HashMap<String, ReplacementParts>, Box<dyn Error>> {
    let module_map = modules
        .into_iter()
        .map(|module| (module.virtual_path.as_str(), module))
        .collect::<HashMap<_, _>>();
    let mut replacements = HashMap::new();

    for record in &bundle.records {
        let module = module_map.get(record.module_path.as_str()).ok_or_else(|| {
            format!(
                "patch target {} was not found in the input binary",
                record.module_path
            )
        })?;
        let actual = record.part.expected_state(module);
        if actual != record.expected {
            return Err(format!(
                "patch does not apply cleanly to {}",
                record.part.workspace_virtual_path(module)
            )
            .into());
        }

        let replacement = replacements
            .entry(record.module_path.clone())
            .or_insert_with(ReplacementParts::default);
        match record.part {
            PatchPartKind::Contents => {
                let PatchBytes::Present(bytes) = &record.replacement else {
                    return Err(format!(
                        "patch for {} cannot remove required contents",
                        record.module_path
                    )
                    .into());
                };
                replacement.contents = RequiredReplacement::Replace(bytes.clone());
            }
            PatchPartKind::SourceMap => {
                replacement.sourcemap = optional_replacement(&record.replacement);
            }
            PatchPartKind::Bytecode => {
                replacement.bytecode = optional_replacement(&record.replacement);
            }
            PatchPartKind::ModuleInfo => {
                replacement.module_info = optional_replacement(&record.replacement);
            }
        }
    }

    Ok(replacements)
}

fn optional_replacement(state: &PatchBytes) -> OptionalReplacement {
    match state {
        PatchBytes::Absent => OptionalReplacement::Remove,
        PatchBytes::Present(bytes) => OptionalReplacement::Replace(bytes.clone()),
    }
}

fn read_workspace_state(
    root: &Path,
    module: &StandaloneModule,
    part: PatchPartKind,
    originally_extracted: bool,
) -> Result<Option<PatchBytes>, Box<dyn Error>> {
    let path = root.join(part.workspace_relative_path(module));
    if path.is_file() {
        return Ok(Some(PatchBytes::Present(fs::read(path)?)));
    }

    if !originally_extracted {
        return Ok(None);
    }

    Ok(Some(PatchBytes::Absent))
}

fn validate_workspace_files<'a>(
    root: &Path,
    modules: impl IntoIterator<Item = &'a StandaloneModule>,
    embedded_files: &[EmbeddedFile],
) -> Result<(), Box<dyn Error>> {
    let mut packable_paths = HashSet::new();
    let mut helper_paths = HashSet::new();

    for module in modules {
        for part in PatchPartKind::ALL {
            packable_paths.insert(part.workspace_relative_path(module));
        }
        helper_paths.insert(
            module
                .sidecar_path(StandaloneSidecarKind::SourceMapJson)
                .trim_start_matches('/')
                .to_string(),
        );
        helper_paths.insert(
            module
                .sidecar_path(StandaloneSidecarKind::ModuleInfoJson)
                .trim_start_matches('/')
                .to_string(),
        );
    }

    let helper_bytes = embedded_files
        .iter()
        .filter_map(|file| match file.kind {
            EmbeddedKind::StandaloneSourceMapJson | EmbeddedKind::StandaloneModuleInfoJson => {
                Some((
                    file.virtual_path.trim_start_matches('/').to_string(),
                    file.bytes.as_slice(),
                ))
            }
            _ => None,
        })
        .collect::<HashMap<_, _>>();

    for relative in collect_workspace_files(root, root)? {
        if packable_paths.contains(&relative) {
            continue;
        }

        if helper_paths.contains(&relative) {
            let actual = fs::read(root.join(&relative))?;
            match helper_bytes.get(&relative) {
                Some(expected) if actual.as_slice() == *expected => continue,
                Some(_) => {
                    return Err(format!(
                        "decoded helper file {} was modified; edit the corresponding .bin file instead",
                        relative
                    )
                    .into());
                }
                None => {
                    return Err(format!(
                        "helper file {} is not packable; remove it or edit the corresponding .bin file instead",
                        relative
                    )
                    .into());
                }
            }
        }

        return Err(format!(
            "workspace file {} is not packable into the standalone binary",
            relative
        )
        .into());
    }

    Ok(())
}

fn collect_workspace_files(root: &Path, current: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            found.extend(collect_workspace_files(root, &path)?);
            continue;
        }
        if !path.is_file() {
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("failed to resolve workspace path {}", path.display()))?;
        found.push(relative.to_string_lossy().replace('\\', "/"));
    }

    found.sort();
    Ok(found)
}

fn render_patch_bundle(bundle: &PatchBundle) -> String {
    let mut out = String::new();
    out.push_str(PATCH_MAGIC);
    out.push('\n');
    if let Some(original_path) = &bundle.original_path {
        out.push_str("original-path=");
        out.push_str(&hex_encode(original_path.as_bytes()));
        out.push('\n');
    }
    out.push_str("record-count=");
    out.push_str(&bundle.records.len().to_string());
    out.push('\n');

    for record in &bundle.records {
        out.push('\n');
        out.push_str("[[record]]\n");
        out.push_str("module-path=");
        out.push_str(&hex_encode(record.module_path.as_bytes()));
        out.push('\n');
        out.push_str("part=");
        out.push_str(record.part.label());
        out.push('\n');
        out.push_str("expected=");
        out.push_str(&record.expected.render());
        out.push('\n');
        out.push_str("replacement=");
        out.push_str(&record.replacement.render());
        out.push('\n');
    }

    out
}

fn parse_patch_bundle(bytes: &[u8]) -> Result<PatchBundle, Box<dyn Error>> {
    let text = std::str::from_utf8(bytes).map_err(|_| "patch file is not valid UTF-8")?;
    let mut lines = text.lines().enumerate().peekable();
    let Some((_, first_line)) = lines.next() else {
        return Err("patch file is empty".into());
    };
    if first_line != PATCH_MAGIC {
        return Err(format!("unsupported patch file header: {first_line}").into());
    }

    let mut original_path = None;
    let mut record_count = None;
    let mut records = Vec::new();
    let mut pending: Option<PendingRecord> = None;

    while let Some((index, line)) = lines.next() {
        if line.is_empty() {
            continue;
        }

        if line == "[[record]]" {
            if let Some(record) = pending.take() {
                records.push(record.finish(index + 1)?);
            }
            pending = Some(PendingRecord::default());
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid patch line {}: {}", index + 1, line))?;
        if let Some(record) = pending.as_mut() {
            record.set(key, value, index + 1)?;
            continue;
        }

        match key {
            "original-path" => {
                original_path = Some(String::from_utf8(hex_decode(value)?)?);
            }
            "record-count" => {
                record_count = Some(value.parse::<usize>()?);
            }
            _ => {
                return Err(
                    format!("unknown patch header field on line {}: {}", index + 1, key).into(),
                );
            }
        }
    }

    if let Some(record) = pending {
        records.push(record.finish(text.lines().count())?);
    }

    if let Some(expected) = record_count {
        if expected != records.len() {
            return Err(format!(
                "patch record count mismatch: header says {}, parsed {}",
                expected,
                records.len()
            )
            .into());
        }
    }

    let mut seen = HashSet::new();
    for record in &records {
        if !seen.insert((record.module_path.clone(), record.part)) {
            return Err(format!(
                "patch contains duplicate record for {} ({})",
                record.module_path,
                record.part.label()
            )
            .into());
        }
    }

    Ok(PatchBundle {
        original_path,
        records,
    })
}

#[derive(Default)]
struct PendingRecord {
    module_path: Option<String>,
    part: Option<PatchPartKind>,
    expected: Option<PatchBytes>,
    replacement: Option<PatchBytes>,
}

impl PendingRecord {
    fn set(&mut self, key: &str, value: &str, line_no: usize) -> Result<(), Box<dyn Error>> {
        match key {
            "module-path" => {
                self.module_path = Some(String::from_utf8(hex_decode(value)?)?);
            }
            "part" => {
                self.part = PatchPartKind::parse(value)
                    .ok_or_else(|| format!("invalid patch part on line {line_no}: {value}"))?
                    .into();
            }
            "expected" => {
                self.expected = Some(PatchBytes::parse(value)?);
            }
            "replacement" => {
                self.replacement = Some(PatchBytes::parse(value)?);
            }
            _ => {
                return Err(
                    format!("unknown patch record field on line {}: {}", line_no, key).into(),
                );
            }
        }

        Ok(())
    }

    fn finish(self, line_no: usize) -> Result<PatchRecord, Box<dyn Error>> {
        Ok(PatchRecord {
            module_path: self.module_path.ok_or_else(|| {
                format!(
                    "patch record ending near line {} is missing module-path",
                    line_no
                )
            })?,
            part: self.part.ok_or_else(|| {
                format!("patch record ending near line {} is missing part", line_no)
            })?,
            expected: self.expected.ok_or_else(|| {
                format!(
                    "patch record ending near line {} is missing expected bytes",
                    line_no
                )
            })?,
            replacement: self.replacement.ok_or_else(|| {
                format!(
                    "patch record ending near line {} is missing replacement bytes",
                    line_no
                )
            })?,
        })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("hex digit overflow"),
    }
}

fn hex_decode(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if value.len() % 2 != 0 {
        return Err(format!("hex field had odd length: {}", value.len()).into());
    }

    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = decode_hex_nibble(bytes[index])?;
        let low = decode_hex_nibble(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    Ok(out)
}

fn decode_hex_nibble(value: u8) -> Result<u8, Box<dyn Error>> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", value as char).into()),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::pack_support::{original_path_path, support_dir};

    #[derive(Debug, Clone, Copy)]
    struct TestModule<'a> {
        name: &'a str,
        contents: &'a [u8],
        sourcemap: &'a [u8],
        bytecode: &'a [u8],
        module_info: &'a [u8],
    }

    #[derive(Debug, Clone, Copy)]
    struct TestModulePointers {
        name: (u32, u32),
        contents: (u32, u32),
        sourcemap: (u32, u32),
        bytecode: (u32, u32),
        module_info: (u32, u32),
    }

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDir {
        path: PathBuf,
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn patch_bundle_round_trips() {
        let bundle = PatchBundle {
            original_path: Some("/tmp/app-binary".to_string()),
            records: vec![PatchRecord {
                module_path: "/$bunfs/root/app.js".to_string(),
                part: PatchPartKind::Contents,
                expected: PatchBytes::Present(b"before".to_vec()),
                replacement: PatchBytes::Present(b"after".to_vec()),
            }],
        };

        let parsed = parse_patch_bundle(render_patch_bundle(&bundle).as_bytes()).unwrap();
        assert_eq!(parsed.original_path, bundle.original_path);
        assert_eq!(parsed.records, bundle.records);
    }

    #[test]
    fn creates_and_applies_patch_bundle() {
        let payload = build_payload(&[TestModule {
            name: "/$bunfs/root/app.js",
            contents: b"// @bun\nconsole.log('entry');\n",
            sourcemap: b"SMAP",
            bytecode: b"",
            module_info: b"META",
        }]);
        let (exe, _) = build_appended_executable(&payload);

        let temp = temp_dir("patch-workflow");
        let workspace = temp.path.join("app.readable");
        let base_binary = temp.path.join("app-binary");
        let patch_file = temp.path.join("app.patch");
        let output_binary = temp.path.join("app-binary.patched");
        fs::create_dir_all(workspace.join("embedded/files/$bunfs/root")).unwrap();
        fs::create_dir_all(support_dir(&workspace)).unwrap();
        fs::write(&base_binary, &exe).unwrap();
        fs::write(base_executable_path(&workspace), &exe).unwrap();
        fs::write(
            original_path_path(&workspace),
            format!("{}\n", base_binary.display()),
        )
        .unwrap();

        let files_root = workspace.join("embedded/files/$bunfs/root");
        fs::write(
            files_root.join("app.js"),
            "// @bun\nconsole.log('patched');\n",
        )
        .unwrap();
        fs::write(files_root.join("app.js.debun-module-info.bin"), b"META").unwrap();

        let summary = create_patch(&PatchConfig {
            from_dir: workspace.clone(),
            out_file: patch_file.clone(),
        })
        .unwrap();
        assert_eq!(summary.record_counts.contents, 1);
        assert_eq!(summary.record_counts.sourcemaps, 1);
        assert_eq!(summary.record_counts.module_infos, 0);

        let apply_summary = apply_patch(&ApplyPatchConfig {
            patch_file,
            input: Some(base_binary),
            out_file: Some(output_binary.clone()),
        })
        .unwrap();
        assert_eq!(apply_summary.record_counts.contents, 1);
        assert_eq!(apply_summary.record_counts.sourcemaps, 1);

        let patched = inspect_executable(&fs::read(output_binary).unwrap())
            .unwrap()
            .unwrap();
        let module = patched.bunfs_modules().next().unwrap();
        assert_eq!(module.bytes, b"// @bun\nconsole.log('patched');\n");
        assert_eq!(module.sourcemap, None);
        assert_eq!(module.module_info.as_deref(), Some(b"META".as_slice()));
    }

    fn temp_dir(label: &str) -> TestDir {
        let unique = format!(
            "debun-{}-{}-{}",
            label,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).unwrap();
        TestDir { path }
    }

    fn push_bytes(body: &mut Vec<u8>, bytes: &[u8]) -> (u32, u32) {
        let offset = u32::try_from(body.len()).unwrap();
        body.extend_from_slice(bytes);
        (offset, u32::try_from(bytes.len()).unwrap())
    }

    fn push_string_pointer(out: &mut Vec<u8>, offset: u32, length: u32) {
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
    }

    fn build_payload(files: &[TestModule<'_>]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut modules = Vec::new();

        for file in files {
            let pointers = TestModulePointers {
                name: push_bytes(&mut body, file.name.as_bytes()),
                contents: push_bytes(&mut body, file.contents),
                sourcemap: push_bytes(&mut body, file.sourcemap),
                bytecode: push_bytes(&mut body, file.bytecode),
                module_info: push_bytes(&mut body, file.module_info),
            };

            push_string_pointer(&mut modules, pointers.name.0, pointers.name.1);
            push_string_pointer(&mut modules, pointers.contents.0, pointers.contents.1);
            push_string_pointer(&mut modules, pointers.sourcemap.0, pointers.sourcemap.1);
            push_string_pointer(&mut modules, pointers.bytecode.0, pointers.bytecode.1);
            push_string_pointer(&mut modules, pointers.module_info.0, pointers.module_info.1);
            push_string_pointer(&mut modules, 0, 0);
            modules.extend_from_slice(&[1, 1, 1, 0]);
        }

        let modules_offset = u32::try_from(body.len()).unwrap();
        body.extend_from_slice(&modules);

        let byte_count = body.len();
        let mut payload = body;
        payload.extend_from_slice(&u64::try_from(byte_count).unwrap().to_le_bytes());
        push_string_pointer(
            &mut payload,
            modules_offset,
            u32::try_from(modules.len()).unwrap(),
        );
        payload.extend_from_slice(&0u32.to_le_bytes());
        push_string_pointer(&mut payload, 0, 0);
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(b"\n---- Bun! ----\n");
        assert!(payload.len() > byte_count);
        payload
    }

    fn build_appended_executable(payload: &[u8]) -> (Vec<u8>, usize) {
        let mut exe = vec![0x7f, b'E', b'L', b'F'];
        exe.resize(128, 0);
        let payload_offset = exe.len();
        exe.extend_from_slice(payload);
        let total_size = u64::try_from(exe.len()).unwrap() + 8;
        exe.extend_from_slice(&total_size.to_le_bytes());
        (exe, payload_offset)
    }
}
