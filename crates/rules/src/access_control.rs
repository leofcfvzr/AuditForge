//! Access control vulnerability detection (SWC-105, SWC-106).
//!
//! Detects functions that perform privileged operations without proper
//! access control modifiers or checks.

use auditforge_core::{Confidence, Finding, Rule, RuleContext, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

static PRIVILEGED_FUNC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ms)function\s+(set\w+|update\w+|change\w+|modify\w+|withdraw\w*|transfer\w*|mint\w*|burn\w*|pause|unpause|upgrade\w*|destroy|selfdestruct|suicide|kill)\s*\([^)]*\)\s*(?:external|public)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}"
    ).unwrap()
});

static ACCESS_MODIFIER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"onlyOwner|onlyAdmin|onlyRole|onlyGovernance|onlyMinter|onlyOperator|requiresAuth|auth|whenNotPaused"
    ).unwrap()
});

static ACCESS_CHECK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"require\s*\(\s*(?:msg\.sender\s*==|hasRole|isOwner|isAdmin|_checkRole|_checkOwner)"
    ).unwrap()
});

static SELFDESTRUCT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"selfdestruct\s*\(|suicide\s*\(").unwrap()
});

static OWNER_CHANGE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"owner\s*=|_owner\s*=|transferOwnership|renounceOwnership").unwrap()
});

#[derive(Default)]
pub struct AccessControlRule;

impl Rule for AccessControlRule {
    fn id(&self) -> &'static str {
        "access-control"
    }

    fn name(&self) -> &'static str {
        "Missing Access Control"
    }

    fn description(&self) -> &'static str {
        "Detects privileged functions (setters, withdrawals, minting, etc.) \
         that lack access control modifiers or require statements, potentially \
         allowing unauthorized users to perform sensitive operations."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn swc_id(&self) -> Option<&'static str> {
        Some("SWC-105")
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-284")
    }

    fn analyze(&self, ctx: &RuleContext) -> Vec<Finding> {
        let source = ctx.source.as_ref();
        let mut findings = Vec::new();

        for cap in PRIVILEGED_FUNC_RE.captures_iter(source) {
            let func_name = cap.get(1).map(|m| m.as_str()).unwrap_or("<unknown>");
            let full_match = cap.get(0).map(|m| m.as_str()).unwrap_or("");
            let func_body = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let match_start = cap.get(0).map(|m| m.start()).unwrap_or(0);

            // Check for access control modifier in function signature
            let has_modifier = ACCESS_MODIFIER_RE.is_match(full_match);
            
            // Check for require-based access control in body
            let has_require_check = ACCESS_CHECK_RE.is_match(func_body);

            if has_modifier || has_require_check {
                continue;
            }

            // Determine severity based on function type
            let (severity, issue_type) = if SELFDESTRUCT_RE.is_match(func_body) {
                (Severity::Critical, "selfdestruct")
            } else if OWNER_CHANGE_RE.is_match(func_body) {
                (Severity::Critical, "ownership change")
            } else if func_name.starts_with("withdraw") || func_name.starts_with("transfer") {
                (Severity::High, "fund transfer")
            } else if func_name.starts_with("mint") || func_name.starts_with("burn") {
                (Severity::High, "token supply modification")
            } else {
                (Severity::Medium, "privileged operation")
            };

            findings.push(
                Finding::new(self.id(), format!("Missing access control on `{}`", func_name))
                    .with_description(format!(
                        "Function `{}` performs {} but has no access control. \
                         Any user can call this function and perform the operation.",
                        func_name, issue_type
                    ))
                    .with_severity(severity)
                    .with_confidence(Confidence::High)
                    .with_location(ctx.make_span(match_start, match_start + full_match.find('{').unwrap_or(50)))
                    .with_suggestion(format!(
                        "Add an access control modifier like `onlyOwner` or a require statement \
                         checking `msg.sender` before performing the {} operation.",
                        issue_type
                    ))
                    .with_swc("SWC-105")
                    .with_cwe("CWE-284"),
            );
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditforge_core::{AstNode, load_default_config};
    use std::path::PathBuf;

    fn make_ctx(source: &str) -> RuleContext {
        RuleContext::new(
            AstNode::new("root", None, vec![]),
            source.to_string(),
            PathBuf::from("test.sol"),
            load_default_config(),
        )
    }

    #[test]
    fn detects_unprotected_setter() {
        let source = r#"
contract Token {
    address owner;
    
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = AccessControlRule;
        let findings = rule.analyze(&ctx);
        
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn ignores_protected_function() {
        let source = r#"
contract Token {
    address owner;
    
    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = AccessControlRule;
        let findings = rule.analyze(&ctx);
        
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn detects_unprotected_withdraw() {
        let source = r#"
contract Vault {
    function withdrawAll() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = AccessControlRule;
        let findings = rule.analyze(&ctx);
        
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }
}

