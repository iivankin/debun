use super::layout::{
    MODULE_RECORD_SIZE_COMPACT, MODULE_RECORD_SIZE_EXTENDED, MODULE_RECORD_SIZE_LEGACY_ENCODING,
    MODULE_RECORD_SIZE_LEGACY_LOADER, MODULE_RECORD_SIZE_WITH_MODULE_INFO, OffsetsLayout,
    SectionLengthWidth, is_bunfs_virtual_path,
};

#[derive(Debug)]
pub(crate) struct StandaloneInspection {
    pub(crate) container: StandaloneContainer,
    pub(crate) payload_bytes: Vec<u8>,
    pub(crate) offsets_layout: OffsetsLayout,
    pub(crate) record_layout: ModuleRecordLayout,
    pub(crate) entry_point_path: Option<String>,
    pub(crate) entry_point_source: Option<String>,
    pub(crate) entry_point_id: u32,
    pub(crate) compile_exec_argv: Option<Vec<u8>>,
    pub(crate) flags_bits: u32,
    pub(crate) modules: Vec<StandaloneModule>,
}

#[derive(Debug)]
pub(crate) enum StandaloneContainer {
    Appended {
        payload_file_offset: usize,
    },
    Section {
        kind: StandaloneSectionKind,
        name: String,
        file_offset: usize,
        bytes: Vec<u8>,
        payload_file_offset: usize,
        length_width: SectionLengthWidth,
    },
}

impl StandaloneContainer {
    pub(crate) fn name(&self) -> Option<&str> {
        match self {
            Self::Appended { .. } => None,
            Self::Section { name, .. } => Some(name),
        }
    }

    pub(crate) const fn file_offset(&self) -> Option<usize> {
        match self {
            Self::Appended { .. } => None,
            Self::Section { file_offset, .. } => Some(*file_offset),
        }
    }

    pub(crate) fn take_bytes(&mut self) -> Option<Vec<u8>> {
        match self {
            Self::Appended { .. } => None,
            Self::Section { bytes, .. } => Some(std::mem::take(bytes)),
        }
    }

    pub(crate) const fn payload_file_offset(&self) -> usize {
        match self {
            Self::Appended {
                payload_file_offset,
            }
            | Self::Section {
                payload_file_offset,
                ..
            } => *payload_file_offset,
        }
    }

    pub(crate) const fn length_width(&self) -> Option<SectionLengthWidth> {
        match self {
            Self::Appended { .. } => None,
            Self::Section { length_width, .. } => Some(*length_width),
        }
    }

    pub(crate) const fn is_macho_section(&self) -> bool {
        matches!(
            self,
            Self::Section {
                kind: StandaloneSectionKind::MachO32 | StandaloneSectionKind::MachO64,
                ..
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StandaloneSectionKind {
    Elf,
    MachO32,
    MachO64,
    Pe32,
    Pe64,
}

impl StandaloneInspection {
    #[cfg(test)]
    pub(crate) const fn record_layout_label(&self) -> &'static str {
        self.record_layout.label()
    }

    pub(crate) fn bunfs_modules(&self) -> impl Iterator<Item = &StandaloneModule> + '_ {
        self.modules.iter().filter(|module| module.is_bunfs_file())
    }
}

#[derive(Debug)]
pub(crate) struct StandaloneModule {
    pub(crate) original_path: String,
    pub(crate) virtual_path: String,
    pub(crate) source_offset: usize,
    pub(crate) bytes: Vec<u8>,
    pub(crate) sourcemap: Option<Vec<u8>>,
    pub(crate) sourcemap_offset: Option<usize>,
    pub(crate) bytecode: Option<Vec<u8>>,
    pub(crate) bytecode_offset: Option<usize>,
    pub(crate) module_info: Option<Vec<u8>>,
    pub(crate) module_info_offset: Option<usize>,
    pub(crate) bytecode_origin_path: Option<String>,
    pub(crate) encoding: u8,
    pub(crate) loader: u8,
    pub(crate) module_format: u8,
    pub(crate) side: u8,
}

impl StandaloneModule {
    pub(crate) fn is_bunfs_file(&self) -> bool {
        is_bunfs_virtual_path(&self.virtual_path)
    }

    pub(crate) fn sidecar_path(&self, kind: StandaloneSidecarKind) -> String {
        format!("{}{}", self.virtual_path, kind.suffix())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum StandaloneSidecarKind {
    SourceMapBinary,
    SourceMapJson,
    BytecodeBinary,
    ModuleInfoBinary,
    ModuleInfoJson,
}

impl StandaloneSidecarKind {
    const fn suffix(self) -> &'static str {
        match self {
            Self::SourceMapBinary => ".debun-sourcemap.bin",
            Self::SourceMapJson => ".debun-sourcemap.json",
            Self::BytecodeBinary => ".debun-bytecode.bin",
            Self::ModuleInfoBinary => ".debun-module-info.bin",
            Self::ModuleInfoJson => ".debun-module-info.json",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ModuleRecordLayout {
    LegacyLoader,
    LegacyEncoding,
    Compact,
    WithModuleInfo,
    Extended,
}

impl ModuleRecordLayout {
    pub(crate) const fn size(self) -> usize {
        match self {
            Self::LegacyLoader => MODULE_RECORD_SIZE_LEGACY_LOADER,
            Self::LegacyEncoding => MODULE_RECORD_SIZE_LEGACY_ENCODING,
            Self::Compact => MODULE_RECORD_SIZE_COMPACT,
            Self::WithModuleInfo => MODULE_RECORD_SIZE_WITH_MODULE_INFO,
            Self::Extended => MODULE_RECORD_SIZE_EXTENDED,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::LegacyLoader => "legacy-loader",
            Self::LegacyEncoding => "legacy-encoding",
            Self::Compact => "compact",
            Self::WithModuleInfo => "with-module-info",
            Self::Extended => "extended",
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ReplacementParts {
    pub(crate) contents: RequiredReplacement,
    pub(crate) sourcemap: OptionalReplacement,
    pub(crate) bytecode: OptionalReplacement,
    pub(crate) module_info: OptionalReplacement,
}

impl ReplacementParts {
    pub(crate) fn is_empty(&self) -> bool {
        self.contents.is_keep()
            && self.sourcemap.is_keep()
            && self.bytecode.is_keep()
            && self.module_info.is_keep()
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum RequiredReplacement {
    #[default]
    Keep,
    Replace(Vec<u8>),
}

impl RequiredReplacement {
    pub(crate) const fn is_keep(&self) -> bool {
        matches!(self, Self::Keep)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum OptionalReplacement {
    #[default]
    Keep,
    Replace(Vec<u8>),
    Remove,
}

impl OptionalReplacement {
    pub(crate) const fn is_keep(&self) -> bool {
        matches!(self, Self::Keep)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ReplacementCounts {
    pub(crate) contents: usize,
    pub(crate) sourcemaps: usize,
    pub(crate) bytecodes: usize,
    pub(crate) module_infos: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct RepackedExecutable {
    pub(crate) bytes: Vec<u8>,
    pub(crate) replacement_counts: ReplacementCounts,
}
