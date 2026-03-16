use std::fmt::Write as _;

use super::SymbolRename;

pub fn symbols_report(renames: &[SymbolRename]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "old_name\tnew_name\tkind\tscope\treferences");
    for rename in renames {
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}",
            rename.old_name, rename.new_name, rename.kind, rename.scope_debug, rename.references
        );
    }
    out
}
