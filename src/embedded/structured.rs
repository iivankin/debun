use crate::{
    standalone::{StandaloneModule, StandaloneSidecarKind},
    standalone_decode::{decode_module_info, decode_serialized_sourcemap},
};

use super::{
    EmbeddedFile, EmbeddedKind,
    detect::{
        detect_kind, standalone_encoding_label, standalone_module_format_label,
        standalone_side_label,
    },
};

struct StandaloneFileContext<'a> {
    module: &'a StandaloneModule,
    module_format: Option<&'static str>,
    side: Option<&'static str>,
}

struct StandaloneFileSpec {
    virtual_path: String,
    kind: EmbeddedKind,
    source_offset: usize,
    bytes: Vec<u8>,
    derived_from: Option<String>,
    standalone_role: Option<&'static str>,
    standalone_encoding: Option<&'static str>,
    standalone_bytecode_origin_path: Option<String>,
}

impl<'a> StandaloneFileContext<'a> {
    fn new(module: &'a StandaloneModule) -> Self {
        Self {
            module,
            module_format: standalone_module_format_label(module.module_format),
            side: standalone_side_label(module.side),
        }
    }

    fn source_offset(&self, offset: Option<usize>) -> usize {
        offset.unwrap_or(self.module.source_offset)
    }

    fn build_file(&self, spec: StandaloneFileSpec) -> EmbeddedFile {
        EmbeddedFile {
            virtual_path: spec.virtual_path,
            kind: spec.kind,
            source_offset: spec.source_offset,
            bytes: spec.bytes,
            derived_from: spec.derived_from,
            standalone_role: spec.standalone_role,
            standalone_encoding: spec.standalone_encoding,
            standalone_loader_id: Some(self.module.loader),
            standalone_module_format: self.module_format,
            standalone_side: self.side,
            standalone_bytecode_origin_path: spec.standalone_bytecode_origin_path,
        }
    }
}

pub(super) fn structured_embedded_files<'a>(
    modules: impl IntoIterator<Item = &'a StandaloneModule>,
) -> Vec<EmbeddedFile> {
    let mut extracted = Vec::new();

    for module in modules {
        let Some(kind) = detect_kind(&module.virtual_path, &module.bytes) else {
            continue;
        };
        let context = StandaloneFileContext::new(module);

        extracted.push(context.build_file(StandaloneFileSpec {
            virtual_path: module.virtual_path.clone(),
            kind,
            source_offset: module.source_offset,
            bytes: module.bytes.clone(),
            derived_from: None,
            standalone_role: Some("contents"),
            standalone_encoding: standalone_encoding_label(module.encoding),
            standalone_bytecode_origin_path: module.bytecode_origin_path.clone(),
        }));

        if let Some(sourcemap) = &module.sourcemap {
            let sourcemap_path = module.sidecar_path(StandaloneSidecarKind::SourceMapBinary);
            extracted.push(context.build_file(StandaloneFileSpec {
                virtual_path: sourcemap_path.clone(),
                kind: EmbeddedKind::StandaloneSourceMap,
                source_offset: context.source_offset(module.sourcemap_offset),
                bytes: sourcemap.clone(),
                derived_from: Some(module.virtual_path.clone()),
                standalone_role: Some("sourcemap"),
                standalone_encoding: None,
                standalone_bytecode_origin_path: None,
            }));

            if let Ok(decoded) = decode_serialized_sourcemap(sourcemap, &module.virtual_path) {
                extracted.push(context.build_file(StandaloneFileSpec {
                    virtual_path: module.sidecar_path(StandaloneSidecarKind::SourceMapJson),
                    kind: EmbeddedKind::StandaloneSourceMapJson,
                    source_offset: context.source_offset(module.sourcemap_offset),
                    bytes: decoded.render_json().into_bytes(),
                    derived_from: Some(sourcemap_path),
                    standalone_role: Some("sourcemap-decoded"),
                    standalone_encoding: None,
                    standalone_bytecode_origin_path: None,
                }));
            }
        }

        if let Some(bytecode) = &module.bytecode {
            extracted.push(context.build_file(StandaloneFileSpec {
                virtual_path: module.sidecar_path(StandaloneSidecarKind::BytecodeBinary),
                kind: EmbeddedKind::StandaloneBytecode,
                source_offset: context.source_offset(module.bytecode_offset),
                bytes: bytecode.clone(),
                derived_from: Some(module.virtual_path.clone()),
                standalone_role: Some("bytecode"),
                standalone_encoding: None,
                standalone_bytecode_origin_path: module.bytecode_origin_path.clone(),
            }));
        }

        if let Some(module_info) = &module.module_info {
            let module_info_path = module.sidecar_path(StandaloneSidecarKind::ModuleInfoBinary);
            extracted.push(context.build_file(StandaloneFileSpec {
                virtual_path: module_info_path.clone(),
                kind: EmbeddedKind::StandaloneModuleInfo,
                source_offset: context.source_offset(module.module_info_offset),
                bytes: module_info.clone(),
                derived_from: Some(module.virtual_path.clone()),
                standalone_role: Some("module-info"),
                standalone_encoding: None,
                standalone_bytecode_origin_path: None,
            }));

            if let Ok(decoded) = decode_module_info(module_info) {
                extracted.push(context.build_file(StandaloneFileSpec {
                    virtual_path: module.sidecar_path(StandaloneSidecarKind::ModuleInfoJson),
                    kind: EmbeddedKind::StandaloneModuleInfoJson,
                    source_offset: context.source_offset(module.module_info_offset),
                    bytes: decoded.render_json().into_bytes(),
                    derived_from: Some(module_info_path),
                    standalone_role: Some("module-info-decoded"),
                    standalone_encoding: None,
                    standalone_bytecode_origin_path: None,
                }));
            }
        }
    }

    extracted
}
