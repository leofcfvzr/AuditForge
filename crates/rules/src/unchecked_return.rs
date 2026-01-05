//! Unchecked call return value detection (SWC-104).
//!
//! Detects low-level calls (call, delegatecall, send) whose return values
//! are not checked, potentially hiding failed operations.

use auditforge_core::{Confidence, Finding, Rule, RuleContext, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

// Match low-level calls that don't capture return value
#[allow(dead_code)]
static UNCHECKED_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*(?:\w+\.)?(?:call|delegatecall|staticcall|send)\s*[\(\{]").unwrap()
});

// Match calls with proper return capture
#[allow(dead_code)]
static CHECKED_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\(\s*bool\s+\w+|bool\s+\w+\s*=.*\.(?:call|send)|if\s*\(.*\.send\s*\(|require\s*\(.*\.send\s*\(").unwrap()
});

// Match lines with calls
static CALL_LINE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^[^/\n]*\.(?:call|delegatecall|staticcall|send)\s*[\(\{][^;]*;").unwrap()
});

#[derive(Default)]
pub struct UncheckedReturnRule;

impl Rule for UncheckedReturnRule {
    fn id(&self) -> &'static str {
        "unchecked-return"
    }

    fn name(&self) -> &'static str {
        "Unchecked Call Return Value"
    }

    fn description(&self) -> &'static str {
        "Detects low-level calls (call, delegatecall, send) whose return values \
         are not checked. Failed calls will silently continue execution, potentially \
         leading to unexpected behavior or loss of funds."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn swc_id(&self) -> Option<&'static str> {
        Some("SWC-104")
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-252")
    }

    fn analyze(&self, ctx: &RuleContext) -> Vec<Finding> {
        let source = ctx.source.as_ref();
        let mut findings = Vec::new();

        for line_match in CALL_LINE_RE.find_iter(source) {
            let line = line_match.as_str();
            let match_start = line_match.start();

            // Skip if the return value is captured/checked
            if line.contains("(bool") || 
               line.contains("bool ") ||
               line.starts_with("if") ||
               line.contains("require") ||
               line.contains("assert") ||
               line.contains("= ") && (line.contains(".call") || line.contains(".send"))
            {
                continue;
            }

            // Determine the call type
            let call_type = if line.contains(".delegatecall") {
                "delegatecall"
            } else if line.contains(".staticcall") {
                "staticcall"
            } else if line.contains(".send") {
                "send"
            } else {
                "call"
            };

            let severity = match call_type {
                "send" => Severity::High,      // ETH transfer
                "delegatecall" => Severity::High,
                _ => Severity::Medium,
            };

            findings.push(
                Finding::new(self.id(), format!("Unchecked `{}` return value", call_type))
                    .with_description(format!(
                        "The return value of `{}` is not checked. If the call fails, \
                         execution will continue as if it succeeded, potentially leading \
                         to incorrect state or loss of funds.",
                        call_type
                    ))
                    .with_severity(severity)
                    .with_confidence(Confidence::High)
                    .with_location(ctx.make_span(match_start, match_start + line.len()))
                    .with_suggestion(format!(
                        "Capture the return value: `(bool success, ) = target.{}(...)` \
                         and check it with `require(success, \"call failed\");`",
                        call_type
                    ))
                    .with_swc("SWC-104")
                    .with_cwe("CWE-252"),
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
    fn detects_unchecked_call() {
        let source = r#"
contract Caller {
    function bad() external {
        target.call{value: 1 ether}("");
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = UncheckedReturnRule;
        let findings = rule.analyze(&ctx);
        
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_checked_call() {
        let source = r#"
contract Caller {
    function good() external {
        (bool success, ) = target.call{value: 1 ether}("");
        require(success, "failed");
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = UncheckedReturnRule;
        let findings = rule.analyze(&ctx);
        
        assert_eq!(findings.len(), 0);
    }
}

