use crate::{
    standalone::StandaloneFile,
    standalone_decode::{decode_module_info, decode_serialized_sourcemap},
};

use super::{
    EmbeddedFile, EmbeddedKind,
    detect::{
        detect_kind, standalone_encoding_label, standalone_module_format_label,
        standalone_side_label,
    },
};

pub(super) fn structured_embedded_files(files: &[StandaloneFile]) -> Vec<EmbeddedFile> {
    let mut extracted = Vec::new();

    for file in files {
        let Some(kind) = detect_kind(&file.virtual_path, &file.bytes) else {
            continue;
        };
        let encoding = standalone_encoding_label(file.encoding);
        let module_format = standalone_module_format_label(file.module_format);
        let side = standalone_side_label(file.side);

        extracted.push(EmbeddedFile {
            virtual_path: file.virtual_path.clone(),
            kind,
            source_offset: file.source_offset,
            bytes: file.bytes.clone(),
            derived_from: None,
            standalone_role: Some("contents"),
            standalone_encoding: encoding,
            standalone_loader_id: Some(file.loader),
            standalone_module_format: module_format,
            standalone_side: side,
            standalone_bytecode_origin_path: file.bytecode_origin_path.clone(),
        });

        if let Some(sourcemap) = &file.sourcemap {
            let sourcemap_path = format!("{}.debun-sourcemap.bin", file.virtual_path);
            extracted.push(EmbeddedFile {
                virtual_path: sourcemap_path.clone(),
                kind: EmbeddedKind::StandaloneSourceMap,
                source_offset: file.sourcemap_offset.unwrap_or(file.source_offset),
                bytes: sourcemap.clone(),
                derived_from: Some(file.virtual_path.clone()),
                standalone_role: Some("sourcemap"),
                standalone_encoding: None,
                standalone_loader_id: Some(file.loader),
                standalone_module_format: module_format,
                standalone_side: side,
                standalone_bytecode_origin_path: None,
            });

            if let Ok(decoded) = decode_serialized_sourcemap(sourcemap, &file.virtual_path) {
                extracted.push(EmbeddedFile {
                    virtual_path: format!("{}.debun-sourcemap.json", file.virtual_path),
                    kind: EmbeddedKind::StandaloneSourceMapJson,
                    source_offset: file.sourcemap_offset.unwrap_or(file.source_offset),
                    bytes: decoded.render_json().into_bytes(),
                    derived_from: Some(sourcemap_path),
                    standalone_role: Some("sourcemap-decoded"),
                    standalone_encoding: None,
                    standalone_loader_id: Some(file.loader),
                    standalone_module_format: module_format,
                    standalone_side: side,
                    standalone_bytecode_origin_path: None,
                });
            }
        }

        if let Some(bytecode) = &file.bytecode {
            extracted.push(EmbeddedFile {
                virtual_path: format!("{}.debun-bytecode.bin", file.virtual_path),
                kind: EmbeddedKind::StandaloneBytecode,
                source_offset: file.bytecode_offset.unwrap_or(file.source_offset),
                bytes: bytecode.clone(),
                derived_from: Some(file.virtual_path.clone()),
                standalone_role: Some("bytecode"),
                standalone_encoding: None,
                standalone_loader_id: Some(file.loader),
                standalone_module_format: module_format,
                standalone_side: side,
                standalone_bytecode_origin_path: file.bytecode_origin_path.clone(),
            });
        }

        if let Some(module_info) = &file.module_info {
            let module_info_path = format!("{}.debun-module-info.bin", file.virtual_path);
            extracted.push(EmbeddedFile {
                virtual_path: module_info_path.clone(),
                kind: EmbeddedKind::StandaloneModuleInfo,
                source_offset: file.module_info_offset.unwrap_or(file.source_offset),
                bytes: module_info.clone(),
                derived_from: Some(file.virtual_path.clone()),
                standalone_role: Some("module-info"),
                standalone_encoding: None,
                standalone_loader_id: Some(file.loader),
                standalone_module_format: module_format,
                standalone_side: side,
                standalone_bytecode_origin_path: None,
            });

            if let Ok(decoded) = decode_module_info(module_info) {
                extracted.push(EmbeddedFile {
                    virtual_path: format!("{}.debun-module-info.json", file.virtual_path),
                    kind: EmbeddedKind::StandaloneModuleInfoJson,
                    source_offset: file.module_info_offset.unwrap_or(file.source_offset),
                    bytes: decoded.render_json().into_bytes(),
                    derived_from: Some(module_info_path),
                    standalone_role: Some("module-info-decoded"),
                    standalone_encoding: None,
                    standalone_loader_id: Some(file.loader),
                    standalone_module_format: module_format,
                    standalone_side: side,
                    standalone_bytecode_origin_path: None,
                });
            }
        }
    }

    extracted
}
