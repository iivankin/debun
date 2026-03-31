use std::{error::Error, fs, path::Path};

use crate::standalone::{ModuleRecordLayout, inspect_executable};

mod detect;
mod metadata;
mod raw;
mod structured;
#[cfg(test)]
mod tests;
mod version;

use metadata::collect_metadata;
use raw::{
    collect_bunfs_paths, extract_embedded_files, find_bun_section, find_first_text_payload_offset,
    printable_strings,
};
use structured::structured_embedded_files;
use version::detect_bun_version;

const MACH_O_MAGIC_64: u32 = 0xfeed_facf;
const MACH_O_MAGIC_32: u32 = 0xfeed_face;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;

const BUN_SECTION_NAMES: &[&str] = &["__BUN", "__bun"];
const BUN_PATH_PREFIXES: &[&[u8]] = &[b"file:///$bunfs/root/", b"/$bunfs/root/", b"B:/~BUN/root/"];
const JS_MARKER: &[u8] = b"// @bun @bytecode @bun-cjs";
const JS_MARKER_FALLBACK: &[u8] = b"// @bun";
const WASM_MAGIC: &[u8] = b"\0asm\x01\0\0\0";
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

#[derive(Debug, Clone)]
pub struct BinaryInspection {
    pub bun_section_name: Option<String>,
    pub bun_section_file_offset: Option<usize>,
    pub bun_section_bytes: Vec<u8>,
    pub bun_section_headerless_offset: Option<usize>,
    pub standalone_graph_file_offset: Option<usize>,
    pub standalone_graph_bytes: Option<Vec<u8>>,
    pub standalone_record_layout: Option<ModuleRecordLayout>,
    pub bun_version: Option<String>,
    pub bunfs_paths: Vec<String>,
    pub metadata: Vec<(String, String)>,
    pub files: Vec<EmbeddedFile>,
    pub entry_point_path: Option<String>,
    pub entry_point_source: Option<String>,
}

impl BinaryInspection {
    pub(crate) fn standalone_layout_label(&self) -> Option<&'static str> {
        self.standalone_record_layout.map(ModuleRecordLayout::label)
    }

    pub(crate) fn standalone_record_size(&self) -> Option<usize> {
        self.standalone_record_layout.map(ModuleRecordLayout::size)
    }
}

#[derive(Debug, Clone)]
pub struct EmbeddedFile {
    pub virtual_path: String,
    pub kind: EmbeddedKind,
    pub source_offset: usize,
    pub bytes: Vec<u8>,
    pub derived_from: Option<String>,
    pub standalone_role: Option<&'static str>,
    pub standalone_encoding: Option<&'static str>,
    pub standalone_loader_id: Option<u8>,
    pub standalone_module_format: Option<&'static str>,
    pub standalone_side: Option<&'static str>,
    pub standalone_bytecode_origin_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedKind {
    JsWrapper,
    Wasm,
    MachO,
    Html,
    Css,
    Text,
    WebManifest,
    Png,
    StandaloneSourceMap,
    StandaloneSourceMapJson,
    StandaloneBytecode,
    StandaloneModuleInfo,
    StandaloneModuleInfoJson,
}

impl EmbeddedKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::JsWrapper => "js-wrapper",
            Self::Wasm => "wasm",
            Self::MachO => "mach-o",
            Self::Html => "html",
            Self::Css => "css",
            Self::Text => "text",
            Self::WebManifest => "webmanifest",
            Self::Png => "png",
            Self::StandaloneSourceMap => "standalone-sourcemap",
            Self::StandaloneSourceMapJson => "standalone-sourcemap-json",
            Self::StandaloneBytecode => "standalone-bytecode",
            Self::StandaloneModuleInfo => "standalone-module-info",
            Self::StandaloneModuleInfoJson => "standalone-module-info-json",
        }
    }
}

pub fn inspect_binary(path: &Path) -> Result<Option<BinaryInspection>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    inspect_binary_bytes(&bytes)
}

fn inspect_binary_bytes(bytes: &[u8]) -> Result<Option<BinaryInspection>, Box<dyn Error>> {
    let bun_version = detect_bun_version(bytes);

    if let Some(standalone) = inspect_executable(bytes)? {
        let raw_container_bytes = standalone.raw_container_bytes.clone();
        let payload_bytes = standalone.payload_bytes.clone();
        let raw_bytes = raw_container_bytes
            .as_deref()
            .unwrap_or(&payload_bytes)
            .to_vec();
        let bun_strings = printable_strings(&raw_bytes);
        let metadata = collect_metadata(&bun_strings);
        let bunfs_paths = standalone
            .bunfs_modules()
            .map(|module| module.virtual_path.clone())
            .collect::<Vec<_>>();
        let structured_files = structured_embedded_files(standalone.bunfs_modules());
        let bunfs_paths = if bunfs_paths.is_empty() {
            collect_bunfs_paths(&raw_bytes)
        } else {
            bunfs_paths
        };

        return Ok(Some(BinaryInspection {
            bun_section_name: standalone.container_name,
            bun_section_file_offset: standalone.raw_container_file_offset,
            bun_section_bytes: raw_container_bytes.unwrap_or_default(),
            bun_section_headerless_offset: standalone
                .raw_container_file_offset
                .map(|_| std::mem::size_of::<u64>()),
            standalone_graph_file_offset: Some(standalone.payload_file_offset),
            standalone_graph_bytes: Some(payload_bytes),
            standalone_record_layout: Some(standalone.record_layout),
            bun_version,
            bunfs_paths,
            metadata,
            files: if structured_files.is_empty() {
                extract_embedded_files(&raw_bytes)
            } else {
                structured_files
            },
            entry_point_path: standalone.entry_point_path,
            entry_point_source: standalone.entry_point_source,
        }));
    }

    let bun_section = find_bun_section(bytes);
    let section_bytes = bun_section
        .and_then(|section| {
            bytes
                .get(section.fileoff..section.fileoff.saturating_add(section.filesize))
                .map(<[u8]>::to_vec)
        })
        .unwrap_or_default();
    if section_bytes.is_empty() {
        return Ok(None);
    }

    let headerless_offset = find_first_text_payload_offset(&section_bytes);
    let bun_strings = printable_strings(&section_bytes);
    let bunfs_paths = collect_bunfs_paths(&section_bytes);
    let metadata = collect_metadata(&bun_strings);
    let files = extract_embedded_files(&section_bytes);

    Ok(Some(BinaryInspection {
        bun_section_name: bun_section.map(|section| section.name.to_string()),
        bun_section_file_offset: bun_section.map(|section| section.fileoff),
        bun_section_bytes: section_bytes,
        bun_section_headerless_offset: headerless_offset,
        standalone_graph_file_offset: None,
        standalone_graph_bytes: None,
        standalone_record_layout: None,
        bun_version,
        bunfs_paths,
        metadata,
        files,
        entry_point_path: None,
        entry_point_source: None,
    }))
}
