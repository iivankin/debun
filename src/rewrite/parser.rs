use std::error::Error;

use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, FunctionBody, Program, Statement};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;

pub(super) fn with_parsed_program(
    source: &str,
    mut visit: impl for<'a> FnMut(&oxc_ast::ast::Program<'a>),
) -> Result<(), Box<dyn Error>> {
    let allocator = Allocator::default();
    let parser_return = Parser::new(&allocator, source, SourceType::cjs().with_typescript(true))
        .with_options(ParseOptions {
            allow_return_outside_function: true,
            parse_regular_expression: true,
            ..ParseOptions::default()
        })
        .parse();

    if !parser_return.errors.is_empty() {
        return Err(format!(
            "failed to parse module body for analysis/rewrite: {} diagnostics",
            parser_return.errors.len()
        )
        .into());
    }

    let program = parser_return.program;
    visit(&program);
    Ok(())
}

pub(super) fn wrapper_body_statements<'a>(program: &'a Program<'a>) -> &'a [Statement<'a>] {
    if let [Statement::ExpressionStatement(statement)] = program.body.as_slice()
        && let Some(body) = expression_function_body(&statement.expression)
    {
        return body.statements.as_slice();
    }

    program.body.as_slice()
}

pub(super) fn expression_function_body<'a>(
    expression: &'a Expression<'a>,
) -> Option<&'a FunctionBody<'a>> {
    match expression {
        Expression::ParenthesizedExpression(parenthesized) => {
            expression_function_body(&parenthesized.expression)
        }
        Expression::FunctionExpression(function) => function.body.as_deref(),
        Expression::ArrowFunctionExpression(function) => Some(&function.body),
        _ => None,
    }
}
