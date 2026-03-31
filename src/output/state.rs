#[derive(Debug, Clone, Copy)]
pub(crate) struct ModuleOutputs {
    pub(crate) directory: &'static str,
    pub(crate) index: &'static str,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct WrittenOutputs {
    pub(crate) symbols: Option<&'static str>,
    pub(crate) modules: Option<ModuleOutputs>,
    pub(crate) embedded_manifest: Option<&'static str>,
    pub(crate) pack_support: Option<&'static str>,
    pub(crate) warnings: Option<&'static str>,
}

impl WrittenOutputs {
    pub(crate) fn primary_output(&self) -> Option<&'static str> {
        self.modules
            .map(|outputs| outputs.index)
            .or(self.embedded_manifest)
            .or(self.warnings)
            .or(self.symbols)
    }
}
