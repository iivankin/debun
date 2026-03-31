use crate::json::{json_bool, json_field, json_string, render_string_array};

#[derive(Debug, Clone)]
pub struct DecodedModuleInfo {
    pub contains_import_meta: bool,
    pub is_typescript: bool,
    pub declared_variables: Vec<String>,
    pub lexical_variables: Vec<String>,
    pub imports: Vec<DecodedImport>,
    pub exports: Vec<DecodedExport>,
    pub requested_modules: Vec<DecodedRequestedModule>,
}

impl DecodedModuleInfo {
    pub fn render_json(&self) -> String {
        let imports = self
            .imports
            .iter()
            .map(DecodedImport::render_json)
            .collect::<Vec<_>>()
            .join(",");
        let exports = self
            .exports
            .iter()
            .map(DecodedExport::render_json)
            .collect::<Vec<_>>()
            .join(",");
        let requested_modules = self
            .requested_modules
            .iter()
            .map(DecodedRequestedModule::render_json)
            .collect::<Vec<_>>()
            .join(",");

        format!(
            concat!(
                "{{",
                "\"flags\":{{\"contains_import_meta\":{},\"is_typescript\":{}}},",
                "\"declared_variables\":[{}],",
                "\"lexical_variables\":[{}],",
                "\"imports\":[{}],",
                "\"exports\":[{}],",
                "\"requested_modules\":[{}]",
                "}}\n"
            ),
            json_bool(self.contains_import_meta),
            json_bool(self.is_typescript),
            render_string_array(&self.declared_variables),
            render_string_array(&self.lexical_variables),
            imports,
            exports,
            requested_modules
        )
    }
}

#[derive(Debug, Clone)]
pub struct DecodedImport {
    pub kind: &'static str,
    pub module: String,
    pub import_name: String,
    pub local_name: String,
    pub type_only: bool,
}

impl DecodedImport {
    pub(super) fn render_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"kind\":{},",
                "\"module\":{},",
                "\"import\":{},",
                "\"local\":{},",
                "\"type_only\":{}",
                "}}"
            ),
            json_string(self.kind),
            json_string(&self.module),
            json_string(&self.import_name),
            json_string(&self.local_name),
            json_bool(self.type_only)
        )
    }
}

#[derive(Debug, Clone)]
pub struct DecodedExport {
    pub kind: &'static str,
    pub export_name: Option<String>,
    pub import_name: Option<String>,
    pub local_name: Option<String>,
    pub module: Option<String>,
}

impl DecodedExport {
    pub(super) fn render_json(&self) -> String {
        let mut fields = vec![json_field("kind", self.kind)];
        if let Some(export_name) = &self.export_name {
            fields.push(json_field("export", export_name));
        }
        if let Some(import_name) = &self.import_name {
            fields.push(json_field("import", import_name));
        }
        if let Some(local_name) = &self.local_name {
            fields.push(json_field("local", local_name));
        }
        if let Some(module) = &self.module {
            fields.push(json_field("module", module));
        }
        format!("{{{}}}", fields.join(","))
    }
}

#[derive(Debug, Clone)]
pub struct DecodedRequestedModule {
    pub module: String,
    pub attributes_kind: &'static str,
    pub host_defined: Option<String>,
}

impl DecodedRequestedModule {
    pub(super) fn render_json(&self) -> String {
        let mut fields = vec![
            json_field("module", &self.module),
            json_field("attributes_kind", self.attributes_kind),
        ];
        if let Some(host_defined) = &self.host_defined {
            fields.push(json_field("host_defined", host_defined));
        }
        format!("{{{}}}", fields.join(","))
    }
}
