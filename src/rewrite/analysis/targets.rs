use std::collections::HashSet;

use oxc_ast::ast::{
    AssignmentTarget, AssignmentTargetMaybeDefault, AssignmentTargetProperty, Expression,
    SimpleAssignmentTarget,
};

pub(super) fn collect_assignment_target_names(
    target: &AssignmentTarget<'_>,
    names: &mut HashSet<String>,
) {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(identifier) => {
            names.insert(identifier.name.as_str().to_string());
        }
        AssignmentTarget::TSAsExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTarget::TSSatisfiesExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTarget::TSNonNullExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTarget::TSTypeAssertion(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTarget::ComputedMemberExpression(_)
        | AssignmentTarget::StaticMemberExpression(_)
        | AssignmentTarget::PrivateFieldExpression(_) => {}
        AssignmentTarget::ArrayAssignmentTarget(pattern) => {
            for item in (&pattern.elements).into_iter().flatten() {
                collect_assignment_target_maybe_default_names(item, names);
            }
            if let Some(rest) = &pattern.rest {
                collect_assignment_target_names(&rest.target, names);
            }
        }
        AssignmentTarget::ObjectAssignmentTarget(pattern) => {
            for property in &pattern.properties {
                match property {
                    AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(property) => {
                        names.insert(property.binding.name.as_str().to_string());
                    }
                    AssignmentTargetProperty::AssignmentTargetPropertyProperty(property) => {
                        collect_assignment_target_maybe_default_names(&property.binding, names);
                    }
                }
            }
            if let Some(rest) = &pattern.rest {
                collect_assignment_target_names(&rest.target, names);
            }
        }
    }
}

fn collect_assignment_target_maybe_default_names(
    target: &AssignmentTargetMaybeDefault<'_>,
    names: &mut HashSet<String>,
) {
    match target {
        AssignmentTargetMaybeDefault::AssignmentTargetIdentifier(identifier) => {
            names.insert(identifier.name.as_str().to_string());
        }
        AssignmentTargetMaybeDefault::TSAsExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTargetMaybeDefault::TSSatisfiesExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTargetMaybeDefault::TSNonNullExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTargetMaybeDefault::TSTypeAssertion(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        AssignmentTargetMaybeDefault::ComputedMemberExpression(_)
        | AssignmentTargetMaybeDefault::StaticMemberExpression(_)
        | AssignmentTargetMaybeDefault::PrivateFieldExpression(_) => {}
        AssignmentTargetMaybeDefault::ArrayAssignmentTarget(pattern) => {
            for item in (&pattern.elements).into_iter().flatten() {
                collect_assignment_target_maybe_default_names(item, names);
            }
            if let Some(rest) = &pattern.rest {
                collect_assignment_target_names(&rest.target, names);
            }
        }
        AssignmentTargetMaybeDefault::ObjectAssignmentTarget(pattern) => {
            for property in &pattern.properties {
                match property {
                    AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(property) => {
                        names.insert(property.binding.name.as_str().to_string());
                    }
                    AssignmentTargetProperty::AssignmentTargetPropertyProperty(property) => {
                        collect_assignment_target_maybe_default_names(&property.binding, names);
                    }
                }
            }
            if let Some(rest) = &pattern.rest {
                collect_assignment_target_names(&rest.target, names);
            }
        }
        AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(target) => {
            collect_assignment_target_names(&target.binding, names);
        }
    }
}

fn collect_assignment_target_names_from_expression(
    expression: &Expression<'_>,
    names: &mut HashSet<String>,
) {
    if let Expression::Identifier(identifier) = expression.get_inner_expression() {
        names.insert(identifier.name.as_str().to_string());
    }
}

pub(super) fn collect_simple_assignment_target_names(
    target: &SimpleAssignmentTarget<'_>,
    names: &mut HashSet<String>,
) {
    match target {
        SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) => {
            names.insert(identifier.name.as_str().to_string());
        }
        SimpleAssignmentTarget::TSAsExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        SimpleAssignmentTarget::TSSatisfiesExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        SimpleAssignmentTarget::TSNonNullExpression(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        SimpleAssignmentTarget::TSTypeAssertion(expression) => {
            collect_assignment_target_names_from_expression(&expression.expression, names);
        }
        SimpleAssignmentTarget::ComputedMemberExpression(_)
        | SimpleAssignmentTarget::StaticMemberExpression(_)
        | SimpleAssignmentTarget::PrivateFieldExpression(_) => {}
    }
}
