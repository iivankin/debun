use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fs,
    io::Write,
    mem::size_of,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::{
    args::{ApplyPatchConfig, PatchConfig, defaults},
    pack_support::{
        base_executable_path, read_original_input_path, resolve_replacements_root,
        resolve_workspace_root, write_atomic_file, write_repacked_executable,
    },
    replacement_workspace::{ModulePart, read_module_part, validate_workspace_files},
    standalone::{
        OptionalReplacement, ReplacementCounts, ReplacementParts, RequiredReplacement,
        StandaloneModule, inspect_executable, repack_executable,
    },
};

// v2 is a length-prefixed little-endian binary stream:
// optional original path, record count, then path/part/expected-hash/replacement records.
const PATCH_MAGIC: &[u8] = b"debun-patch/v2\n";
const SHA256_LEN: usize = 32;
const STATE_ABSENT: u8 = 0;
const STATE_PRESENT: u8 = 1;

pub(crate) struct PatchSummary {
    pub(crate) replacements_root: PathBuf,
    pub(crate) record_counts: ReplacementCounts,
}

pub(crate) struct ApplyPatchSummary {
    pub(crate) input_file: PathBuf,
    pub(crate) out_file: PathBuf,
    pub(crate) record_counts: ReplacementCounts,
}

#[derive(Debug)]
struct PatchBundle {
    original_path: Option<String>,
    records: Vec<PatchRecord>,
}

#[derive(Debug, PartialEq, Eq)]
struct PatchRecord {
    module_path: String,
    part: ModulePart,
    expected: ExpectedState,
    replacement: PatchBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedState {
    Absent,
    Sha256([u8; SHA256_LEN]),
}

#[derive(Debug, PartialEq, Eq)]
enum PatchBytes {
    Absent,
    Present(Vec<u8>),
}

impl ExpectedState {
    fn from_original(part: ModulePart, module: &StandaloneModule) -> Self {
        part.original_bytes(module)
            .map_or(Self::Absent, |bytes| Self::Sha256(sha256(bytes)))
    }

    fn matches_original(&self, part: ModulePart, module: &StandaloneModule) -> bool {
        match (self, part.original_bytes(module)) {
            (Self::Absent, None) => true,
            (Self::Sha256(expected), Some(actual)) => *expected == sha256(actual),
            _ => false,
        }
    }
}

impl PatchBytes {
    const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    fn matches_original(&self, part: ModulePart, module: &StandaloneModule) -> bool {
        match (self, part.original_bytes(module)) {
            (Self::Absent, None) => true,
            (Self::Present(candidate), Some(original)) => candidate == original,
            _ => false,
        }
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
    validate_workspace_files(&replacements_root, standalone.bunfs_modules())?;

    let mut records = Vec::new();
    let mut counts = ReplacementCounts::default();

    for module in standalone.bunfs_modules() {
        for part in ModulePart::ALL {
            let replacement = read_workspace_state(&replacements_root, module, part)?;
            let Some(replacement) = replacement else {
                continue;
            };
            if replacement.matches_original(part, module) {
                continue;
            }
            if part == ModulePart::Contents && replacement.is_absent() {
                return Err(format!(
                    "workspace file {} is missing; contents patches cannot delete BunFS modules",
                    part.virtual_path(module)
                )
                .into());
            }

            part.count(&mut counts);
            records.push(PatchRecord {
                module_path: module.virtual_path.clone(),
                part,
                expected: ExpectedState::from_original(part, module),
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

    write_atomic_file(&config.out_file, |file| write_patch_bundle(file, &bundle))?;

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
    let section_backed_macho = standalone.container.is_macho_section();
    let record_counts = bundle.counts();
    let replacements = build_replacements(bundle.records, standalone.bunfs_modules())?;
    let modified = !replacements.is_empty();
    let output_bytes = if modified {
        repack_executable(&original_bytes, standalone, &replacements)?.bytes
    } else {
        original_bytes
    };

    write_repacked_executable(
        &out_file,
        &output_bytes,
        original_permissions,
        section_backed_macho && modified,
    )?;

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
    records: Vec<PatchRecord>,
    modules: impl IntoIterator<Item = &'a StandaloneModule>,
) -> Result<HashMap<String, ReplacementParts>, Box<dyn Error>> {
    let module_map = modules
        .into_iter()
        .map(|module| (module.virtual_path.as_str(), module))
        .collect::<HashMap<_, _>>();
    let mut replacements = HashMap::new();

    for record in records {
        let module = module_map.get(record.module_path.as_str()).ok_or_else(|| {
            format!(
                "patch target {} was not found in the input binary",
                record.module_path
            )
        })?;
        if !record.expected.matches_original(record.part, module) {
            return Err(format!(
                "patch does not apply cleanly to {}",
                record.part.virtual_path(module)
            )
            .into());
        }

        let replacement = replacements
            .entry(record.module_path)
            .or_insert_with(ReplacementParts::default);
        match record.part {
            ModulePart::Contents => {
                let PatchBytes::Present(bytes) = record.replacement else {
                    return Err(format!(
                        "patch for {} cannot remove required contents",
                        module.virtual_path
                    )
                    .into());
                };
                replacement.contents = RequiredReplacement::Replace(bytes);
            }
            ModulePart::SourceMap => {
                replacement.sourcemap = optional_replacement(record.replacement);
            }
            ModulePart::Bytecode => {
                replacement.bytecode = optional_replacement(record.replacement);
            }
            ModulePart::ModuleInfo => {
                replacement.module_info = optional_replacement(record.replacement);
            }
        }
    }

    Ok(replacements)
}

fn optional_replacement(state: PatchBytes) -> OptionalReplacement {
    match state {
        PatchBytes::Absent => OptionalReplacement::Remove,
        PatchBytes::Present(bytes) => OptionalReplacement::Replace(bytes),
    }
}

fn read_workspace_state(
    root: &Path,
    module: &StandaloneModule,
    part: ModulePart,
) -> Result<Option<PatchBytes>, Box<dyn Error>> {
    if let Some(bytes) = read_module_part(root, module, part)? {
        return Ok(Some(PatchBytes::Present(bytes)));
    }
    Ok(part
        .original_bytes(module)
        .is_some()
        .then_some(PatchBytes::Absent))
}

fn write_patch_bundle(writer: &mut impl Write, bundle: &PatchBundle) -> Result<(), Box<dyn Error>> {
    writer.write_all(PATCH_MAGIC)?;
    write_optional_string(writer, bundle.original_path.as_deref())?;
    write_u32(
        writer,
        u32::try_from(bundle.records.len()).map_err(|_| "patch record count exceeded u32")?,
    )?;

    for record in &bundle.records {
        write_bytes(writer, record.module_path.as_bytes(), "module path")?;
        writer.write_all(&[module_part_tag(record.part)])?;
        match record.expected {
            ExpectedState::Absent => writer.write_all(&[STATE_ABSENT])?,
            ExpectedState::Sha256(hash) => {
                writer.write_all(&[STATE_PRESENT])?;
                writer.write_all(&hash)?;
            }
        }
        match &record.replacement {
            PatchBytes::Absent => writer.write_all(&[STATE_ABSENT])?,
            PatchBytes::Present(bytes) => {
                writer.write_all(&[STATE_PRESENT])?;
                write_bytes(writer, bytes, "replacement")?;
            }
        }
    }

    Ok(())
}

fn write_optional_string(
    writer: &mut impl Write,
    value: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    match value {
        None => writer.write_all(&[STATE_ABSENT])?,
        Some(value) => {
            writer.write_all(&[STATE_PRESENT])?;
            write_bytes(writer, value.as_bytes(), "original path")?;
        }
    }
    Ok(())
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8], field: &str) -> Result<(), Box<dyn Error>> {
    let len = u32::try_from(bytes.len()).map_err(|_| format!("patch {field} exceeded u32"))?;
    write_u32(writer, len)?;
    writer.write_all(bytes)?;
    Ok(())
}

fn write_u32(writer: &mut impl Write, value: u32) -> Result<(), Box<dyn Error>> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn parse_patch_bundle(bytes: &[u8]) -> Result<PatchBundle, Box<dyn Error>> {
    if bytes.is_empty() {
        return Err("patch file is empty".into());
    }
    if !bytes.starts_with(PATCH_MAGIC) {
        let header_end = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |index| index)
            .min(64);
        let header = String::from_utf8_lossy(&bytes[..header_end]);
        return Err(format!("unsupported patch file header: {header}").into());
    }

    let mut reader = PatchReader::new(bytes, PATCH_MAGIC.len());
    let original_path = match reader.read_state("original path state")? {
        STATE_ABSENT => None,
        STATE_PRESENT => Some(reader.read_string("original path")?),
        state => return Err(format!("invalid original path state: {state}").into()),
    };
    let record_count = reader.read_u32("record count")?;
    let mut records = Vec::new();
    let mut seen = HashSet::new();

    for _ in 0..record_count {
        let module_path = reader.read_string("module path")?;
        let part_tag = reader.read_state("module part")?;
        let part = module_part_from_tag(part_tag)
            .ok_or_else(|| format!("invalid patch module part: {part_tag}"))?;
        if !seen.insert((module_path.clone(), part)) {
            return Err(format!(
                "patch contains duplicate record for {} ({})",
                module_path,
                part.label()
            )
            .into());
        }

        let expected = match reader.read_state("expected state")? {
            STATE_ABSENT => ExpectedState::Absent,
            STATE_PRESENT => {
                let mut hash = [0; SHA256_LEN];
                hash.copy_from_slice(reader.read_exact(SHA256_LEN, "expected SHA-256")?);
                ExpectedState::Sha256(hash)
            }
            state => return Err(format!("invalid expected state: {state}").into()),
        };
        let replacement = match reader.read_state("replacement state")? {
            STATE_ABSENT => PatchBytes::Absent,
            STATE_PRESENT => PatchBytes::Present(reader.read_bytes("replacement")?.to_vec()),
            state => return Err(format!("invalid replacement state: {state}").into()),
        };
        records.push(PatchRecord {
            module_path,
            part,
            expected,
            replacement,
        });
    }

    reader.finish()?;
    Ok(PatchBundle {
        original_path,
        records,
    })
}

struct PatchReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PatchReader<'a> {
    const fn new(bytes: &'a [u8], offset: usize) -> Self {
        Self { bytes, offset }
    }

    fn read_state(&mut self, field: &str) -> Result<u8, Box<dyn Error>> {
        Ok(self.read_exact(1, field)?[0])
    }

    fn read_u32(&mut self, field: &str) -> Result<u32, Box<dyn Error>> {
        let bytes: [u8; 4] = self
            .read_exact(size_of::<u32>(), field)?
            .try_into()
            .expect("read_exact returned the requested length");
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_bytes(&mut self, field: &str) -> Result<&'a [u8], Box<dyn Error>> {
        let len = usize::try_from(self.read_u32(field)?)
            .map_err(|_| format!("patch {field} length exceeded usize"))?;
        self.read_exact(len, field)
    }

    fn read_string(&mut self, field: &str) -> Result<String, Box<dyn Error>> {
        let bytes = self.read_bytes(field)?;
        let value =
            std::str::from_utf8(bytes).map_err(|_| format!("patch {field} is not valid UTF-8"))?;
        Ok(value.to_string())
    }

    fn read_exact(&mut self, len: usize, field: &str) -> Result<&'a [u8], Box<dyn Error>> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| format!("patch {field} length overflowed"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| format!("patch ended while reading {field} at byte {}", self.offset))?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), Box<dyn Error>> {
        if self.offset != self.bytes.len() {
            return Err(format!(
                "patch contains {} trailing bytes",
                self.bytes.len() - self.offset
            )
            .into());
        }
        Ok(())
    }
}

const fn module_part_tag(part: ModulePart) -> u8 {
    match part {
        ModulePart::Contents => 0,
        ModulePart::SourceMap => 1,
        ModulePart::Bytecode => 2,
        ModulePart::ModuleInfo => 3,
    }
}

const fn module_part_from_tag(tag: u8) -> Option<ModulePart> {
    match tag {
        0 => Some(ModulePart::Contents),
        1 => Some(ModulePart::SourceMap),
        2 => Some(ModulePart::Bytecode),
        3 => Some(ModulePart::ModuleInfo),
        _ => None,
    }
}

fn sha256(bytes: &[u8]) -> [u8; SHA256_LEN] {
    Sha256::digest(bytes).into()
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
                part: ModulePart::Contents,
                expected: ExpectedState::Sha256(sha256(b"before")),
                replacement: PatchBytes::Present(b"after".to_vec()),
            }],
        };

        let mut encoded = Vec::new();
        write_patch_bundle(&mut encoded, &bundle).unwrap();
        let parsed = parse_patch_bundle(&encoded).unwrap();
        assert_eq!(parsed.original_path, bundle.original_path);
        assert_eq!(parsed.records, bundle.records);
    }

    #[test]
    fn rejects_truncated_legacy_and_duplicate_patches() {
        let truncated = parse_patch_bundle(PATCH_MAGIC).expect_err("header alone is incomplete");
        assert!(truncated.to_string().contains("original path state"));

        let legacy = parse_patch_bundle(b"debun-patch/v1\nrecord-count=0\n")
            .expect_err("v1 must not be accepted after the hard cutover");
        assert!(legacy.to_string().contains("unsupported patch file header"));

        let record = || PatchRecord {
            module_path: "/$bunfs/root/app.js".to_string(),
            part: ModulePart::Contents,
            expected: ExpectedState::Absent,
            replacement: PatchBytes::Present(b"after".to_vec()),
        };
        let bundle = PatchBundle {
            original_path: None,
            records: vec![record(), record()],
        };
        let mut encoded = Vec::new();
        write_patch_bundle(&mut encoded, &bundle).unwrap();
        let duplicate =
            parse_patch_bundle(&encoded).expect_err("duplicate records must be rejected");
        assert!(duplicate.to_string().contains("duplicate record"));
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
        let mismatched_binary = temp.path.join("app-binary.mismatched");
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
        assert!(fs::read(&patch_file).unwrap().starts_with(PATCH_MAGIC));

        let mismatched_payload = build_payload(&[TestModule {
            name: "/$bunfs/root/app.js",
            contents: b"// @bun\nconsole.log('different base');\n",
            sourcemap: b"SMAP",
            bytecode: b"",
            module_info: b"META",
        }]);
        let (mismatched_exe, _) = build_appended_executable(&mismatched_payload);
        fs::write(&mismatched_binary, mismatched_exe).unwrap();
        let mismatch = apply_patch(&ApplyPatchConfig {
            patch_file: patch_file.clone(),
            input: Some(mismatched_binary),
            out_file: Some(temp.path.join("mismatch-output")),
        });
        let Err(mismatch) = mismatch else {
            panic!("the expected SHA-256 must reject a different base module");
        };
        assert!(mismatch.to_string().contains("does not apply cleanly"));

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
