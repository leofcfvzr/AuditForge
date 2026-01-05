//! Delegatecall vulnerability detection (SWC-112).
//!
//! Detects dangerous uses of delegatecall, especially with user-controlled
//! addresses or in proxy patterns without proper access controls.

use auditforge_core::{Confidence, Finding, Rule, RuleContext, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

static DELEGATECALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\w+)\.delegatecall\s*\(").unwrap()
});

static USER_INPUT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"msg\.sender|msg\.data|tx\.origin|_to|_target|_impl|_address|_contract").unwrap()
});

static ACCESS_CONTROL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"onlyOwner|onlyAdmin|require\s*\(\s*msg\.sender\s*==\s*owner|Ownable|AccessControl").unwrap()
});

#[derive(Default)]
pub struct DelegatecallRule;

impl Rule for DelegatecallRule {
    fn id(&self) -> &'static str {
        "delegatecall"
    }

    fn name(&self) -> &'static str {
        "Unsafe Delegatecall"
    }

    fn description(&self) -> &'static str {
        "Detects delegatecall usage that may allow arbitrary code execution. \
         Delegatecall preserves the caller's context (msg.sender, storage) which \
         can lead to storage corruption or unauthorized actions if the target \
         address is not properly controlled."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn swc_id(&self) -> Option<&'static str> {
        Some("SWC-112")
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-829")
    }

    fn analyze(&self, ctx: &RuleContext) -> Vec<Finding> {
        let source = ctx.source.as_ref();
        let mut findings = Vec::new();

        for cap in DELEGATECALL_RE.captures_iter(source) {
            let target = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let match_start = cap.get(0).map(|m| m.start()).unwrap_or(0);
            let match_end = cap.get(0).map(|m| m.end()).unwrap_or(0);

            // Get surrounding context (function)
            let context_start = source[..match_start].rfind("function").unwrap_or(0);
            let context_end = source[match_end..].find('}').map(|i| match_end + i).unwrap_or(source.len());
            let context = &source[context_start..context_end];

            // Check if target could be user-controlled
            let is_user_controlled = USER_INPUT_RE.is_match(target) || 
                context.contains(&format!("= {};", target)) ||
                context.contains(&format!("({}", target));

            // Check for access controls
            let has_access_control = ACCESS_CONTROL_RE.is_match(context);

            let (severity, confidence, description) = if is_user_controlled && !has_access_control {
                (
                    Severity::Critical,
                    Confidence::High,
                    format!(
                        "Delegatecall to potentially user-controlled address `{}` without access control. \
                         An attacker could point this to a malicious contract and execute arbitrary code \
                         in this contract's context.",
                        target
                    ),
                )
            } else if !has_access_control {
                (
                    Severity::High,
                    Confidence::Medium,
                    format!(
                        "Delegatecall to `{}` without visible access control. Ensure the target address \
                         cannot be manipulated by unauthorized users.",
                        target
                    ),
                )
            } else {
                (
                    Severity::Low,
                    Confidence::Low,
                    format!(
                        "Delegatecall to `{}` detected. While access control is present, ensure \
                         the target contract's storage layout is compatible.",
                        target
                    ),
                )
            };

            findings.push(
                Finding::new(self.id(), format!("Delegatecall to `{}`", target))
                    .with_description(description)
                    .with_severity(severity)
                    .with_confidence(confidence)
                    .with_location(ctx.make_span(match_start, match_end))
                    .with_suggestion(
                        "Ensure delegatecall targets are immutable or protected by strong access controls. \
                         Consider using OpenZeppelin's transparent or UUPS proxy patterns for upgrades."
                    )
                    .with_swc("SWC-112")
                    .with_cwe("CWE-829"),
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
    fn detects_unprotected_delegatecall() {
        let source = r#"
contract Proxy {
    function forward(address target, bytes calldata data) external {
        target.delegatecall(data);
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = DelegatecallRule;
        let findings = rule.analyze(&ctx);
        
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn lower_severity_with_access_control() {
        let source = r#"
contract Proxy {
    address owner;
    
    function forward(address target, bytes calldata data) external onlyOwner {
        target.delegatecall(data);
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = DelegatecallRule;
        let findings = rule.analyze(&ctx);
        
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }
}

