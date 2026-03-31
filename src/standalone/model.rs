use super::layout::{
    MODULE_RECORD_SIZE_COMPACT, MODULE_RECORD_SIZE_EXTENDED, MODULE_RECORD_SIZE_WITH_MODULE_INFO,
    is_bunfs_virtual_path,
};

#[derive(Debug, Clone)]
pub(crate) struct StandaloneInspection {
    pub(crate) container_name: Option<String>,
    pub(crate) raw_container_file_offset: Option<usize>,
    pub(crate) raw_container_bytes: Option<Vec<u8>>,
    pub(crate) payload_file_offset: usize,
    pub(crate) payload_bytes: Vec<u8>,
    pub(crate) record_layout: ModuleRecordLayout,
    pub(crate) entry_point_path: Option<String>,
    pub(crate) entry_point_source: Option<String>,
    pub(crate) entry_point_id: u32,
    pub(crate) compile_exec_argv: Option<Vec<u8>>,
    pub(crate) flags_bits: u32,
    pub(crate) modules: Vec<StandaloneModule>,
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

#[derive(Debug, Clone)]
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
    Compact,
    WithModuleInfo,
    Extended,
}

impl ModuleRecordLayout {
    pub(crate) const fn size(self) -> usize {
        match self {
            Self::Compact => MODULE_RECORD_SIZE_COMPACT,
            Self::WithModuleInfo => MODULE_RECORD_SIZE_WITH_MODULE_INFO,
            Self::Extended => MODULE_RECORD_SIZE_EXTENDED,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::WithModuleInfo => "with-module-info",
            Self::Extended => "extended",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ReplacementParts {
    pub(crate) contents: Option<Vec<u8>>,
    pub(crate) sourcemap: Option<Vec<u8>>,
    pub(crate) bytecode: Option<Vec<u8>>,
    pub(crate) module_info: Option<Vec<u8>>,
}

impl ReplacementParts {
    pub(crate) const fn is_empty(&self) -> bool {
        self.contents.is_none()
            && self.sourcemap.is_none()
            && self.bytecode.is_none()
            && self.module_info.is_none()
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
