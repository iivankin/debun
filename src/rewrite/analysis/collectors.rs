use std::collections::HashSet;

use oxc_ast::ast::{AssignmentExpression, UpdateExpression};
use oxc_ast_visit::{Visit, walk};

use super::targets::{collect_assignment_target_names, collect_simple_assignment_target_names};

#[derive(Default)]
pub(super) struct LazyExportCollector {
    pub(super) locals: HashSet<String>,
    pub(super) assigned: HashSet<String>,
}

#[derive(Default)]
pub(super) struct ExternalReferenceCollector {
    pub(super) locals: HashSet<String>,
    pub(super) references: HashSet<String>,
}

impl<'a> Visit<'a> for LazyExportCollector {
    fn visit_binding_identifier(&mut self, it: &oxc_ast::ast::BindingIdentifier<'a>) {
        self.locals.insert(it.name.as_str().to_string());
        walk::walk_binding_identifier(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        collect_assignment_target_names(&it.left, &mut self.assigned);
        walk::walk_assignment_expression(self, it);
    }

    fn visit_update_expression(&mut self, it: &UpdateExpression<'a>) {
        collect_simple_assignment_target_names(&it.argument, &mut self.assigned);
        walk::walk_update_expression(self, it);
    }
}

impl<'a> Visit<'a> for ExternalReferenceCollector {
    fn visit_binding_identifier(&mut self, it: &oxc_ast::ast::BindingIdentifier<'a>) {
        self.locals.insert(it.name.as_str().to_string());
        walk::walk_binding_identifier(self, it);
    }

    fn visit_identifier_reference(&mut self, it: &oxc_ast::ast::IdentifierReference<'a>) {
        self.references.insert(it.name.as_str().to_string());
        walk::walk_identifier_reference(self, it);
    }
}
