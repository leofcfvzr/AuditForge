//! Uninitialized storage pointer detection (SWC-109).
//!
//! Detects local storage variables that may point to arbitrary storage slots,
//! potentially allowing storage corruption.

use auditforge_core::{Confidence, Finding, Rule, RuleContext, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

// Match uninitialized storage pointers in functions
static STORAGE_POINTER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*(struct\s+)?(\w+)\s+storage\s+(\w+)\s*;").unwrap()
});

// Match proper storage assignments
#[allow(dead_code)]
static STORAGE_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\w+)\s+storage\s+(\w+)\s*=").unwrap()
});

// Match function scope
static FUNCTION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?ms)function\s+\w+[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}").unwrap()
});

#[derive(Default)]
pub struct UninitializedStorageRule;

impl Rule for UninitializedStorageRule {
    fn id(&self) -> &'static str {
        "uninitialized-storage"
    }

    fn name(&self) -> &'static str {
        "Uninitialized Storage Pointer"
    }

    fn description(&self) -> &'static str {
        "Detects storage pointers declared without initialization inside functions. \
         Uninitialized storage pointers point to storage slot 0 by default, which \
         can lead to unintended storage overwrites."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn swc_id(&self) -> Option<&'static str> {
        Some("SWC-109")
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-824")
    }

    fn analyze(&self, ctx: &RuleContext) -> Vec<Finding> {
        let source = ctx.source.as_ref();
        let mut findings = Vec::new();

        // Find all functions and check for uninitialized storage pointers
        for func_cap in FUNCTION_RE.captures_iter(source) {
            let func_body = func_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let func_start = func_cap.get(0).map(|m| m.start()).unwrap_or(0);
            let body_offset = func_cap.get(1).map(|m| m.start() - func_start).unwrap_or(0);

            for storage_cap in STORAGE_POINTER_RE.captures_iter(func_body) {
                let var_name = storage_cap.get(3).map(|m| m.as_str()).unwrap_or("<unknown>");
                let type_name = storage_cap.get(2).map(|m| m.as_str()).unwrap_or("unknown");
                let match_start = storage_cap.get(0).map(|m| m.start()).unwrap_or(0);
                let match_str = storage_cap.get(0).map(|m| m.as_str()).unwrap_or("");

                // This pattern catches declarations without assignment (ending in ;)
                let abs_pos = func_start + body_offset + match_start;

                findings.push(
                    Finding::new(self.id(), format!("Uninitialized storage pointer `{}`", var_name))
                        .with_description(format!(
                            "Storage pointer `{}` of type `{}` is declared without initialization. \
                             It will point to storage slot 0, potentially overwriting the first \
                             state variable when written to.",
                            var_name, type_name
                        ))
                        .with_severity(Severity::High)
                        .with_confidence(Confidence::High)
                        .with_location(ctx.make_span(abs_pos, abs_pos + match_str.len()))
                        .with_suggestion(format!(
                            "Initialize the storage pointer: `{} storage {} = someStateVariable;` \
                             or use memory instead if a copy is acceptable.",
                            type_name, var_name
                        ))
                        .with_swc("SWC-109")
                        .with_cwe("CWE-824"),
                );
            }
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
    fn detects_uninitialized_storage() {
        let source = r#"
contract Vulnerable {
    struct User {
        uint256 id;
        address addr;
    }
    
    User[] users;
    
    function bad() external {
        User storage user;
        user.id = 1;
        user.addr = msg.sender;
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = UninitializedStorageRule;
        let findings = rule.analyze(&ctx);
        
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_initialized_storage() {
        let source = r#"
contract Safe {
    struct User {
        uint256 id;
        address addr;
    }
    
    User[] users;
    
    function good() external {
        User storage user = users[0];
        user.id = 1;
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = UninitializedStorageRule;
        let findings = rule.analyze(&ctx);
        
        assert!(findings.is_empty());
    }
}

