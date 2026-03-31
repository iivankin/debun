use oxc_allocator::Allocator;
use oxc_codegen::{Codegen, CodegenOptions, IndentChar};
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::{Scoping, SemanticBuilder};
use oxc_span::SourceType;

use crate::{args::Config, split::preferred_commonjs_names};

use super::{SymbolRename, rename::rename_symbols};

pub(super) struct CoreTransformArtifacts {
    pub(super) formatted: String,
    pub(super) renamed: String,
    pub(super) renames: Vec<SymbolRename>,
    pub(super) parse_errors: Vec<String>,
    pub(super) semantic_errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParseStrategy {
    Unambiguous,
    CommonJs,
}

impl ParseStrategy {
    fn source_type(self) -> SourceType {
        match self {
            Self::Unambiguous => SourceType::unambiguous(),
            Self::CommonJs => SourceType::cjs(),
        }
    }

    const fn preference_rank(self) -> usize {
        match self {
            Self::Unambiguous => 0,
            Self::CommonJs => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DiagnosticScore {
    parse_errors: usize,
    semantic_errors: usize,
    preference_rank: usize,
}

impl CoreTransformArtifacts {
    fn score(&self, strategy: ParseStrategy) -> DiagnosticScore {
        DiagnosticScore {
            parse_errors: self.parse_errors.len(),
            semantic_errors: self.semantic_errors.len(),
            preference_rank: strategy.preference_rank(),
        }
    }
}

pub(super) fn transform_source_best_effort(
    config: &Config,
    source: &str,
) -> Result<CoreTransformArtifacts, Box<dyn std::error::Error>> {
    // Bun standalone entrypoints often mix CommonJS wrappers with ESM-only
    // syntax like static imports, `import.meta`, and top-level `await`.
    // Start with Oxc's "unambiguous" mode, then fall back to explicit CJS
    // when it produces fewer diagnostics.
    let mut best_candidate =
        transform_source_for_strategy(config, source, ParseStrategy::Unambiguous);
    let best_score = best_candidate.score(ParseStrategy::Unambiguous);

    {
        let strategy = ParseStrategy::CommonJs;
        let candidate = transform_source_for_strategy(config, source, strategy);
        let score = candidate.score(strategy);
        if score < best_score {
            best_candidate = candidate;
        }
    }

    Ok(best_candidate)
}

fn transform_source_for_strategy(
    config: &Config,
    source: &str,
    strategy: ParseStrategy,
) -> CoreTransformArtifacts {
    let allocator = Allocator::default();
    let parser_return = Parser::new(&allocator, source, strategy.source_type())
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            parse_regular_expression: true,
            ..ParseOptions::default()
        })
        .parse();

    let parse_errors = parser_return
        .errors
        .into_iter()
        .map(|error| format!("{:?}", error.with_source_code(source.to_owned())))
        .collect::<Vec<_>>();

    let program = parser_return.program;
    let formatted = render(&program, source, None);

    let semantic_return = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&program);
    let semantic_errors = semantic_return
        .errors
        .into_iter()
        .map(|error| format!("{:?}", error.with_source_code(source.to_owned())))
        .collect::<Vec<_>>();

    let preferred_names = preferred_commonjs_names(&program);
    let mut scoping = semantic_return.semantic.into_scoping();
    let symbol_renames = if config.rename_symbols {
        rename_symbols(&mut scoping, &config.module_name, &preferred_names)
    } else {
        Vec::new()
    };
    let renamed_source = render(&program, source, Some(scoping));

    CoreTransformArtifacts {
        formatted,
        renamed: renamed_source,
        renames: symbol_renames,
        parse_errors,
        semantic_errors,
    }
}

fn render(program: &oxc_ast::ast::Program<'_>, source: &str, scoping: Option<Scoping>) -> String {
    let options = CodegenOptions {
        indent_char: IndentChar::Space,
        indent_width: 2,
        ..CodegenOptions::default()
    };

    Codegen::new()
        .with_options(options)
        .with_source_text(source)
        .with_scoping(scoping)
        .build(program)
        .code
}
