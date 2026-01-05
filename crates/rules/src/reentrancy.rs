//! Reentrancy vulnerability detection (SWC-107).
//!
//! Detects external calls in public/external functions that may allow
//! reentrancy attacks when state is modified after the call.

use auditforge_core::{Confidence, Finding, Rule, RuleContext, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

static FUNC_HEADER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*(?:public|external)[^{]*\{").unwrap()
});

static EXTERNAL_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\.call\s*[\{\(]|\.delegatecall\s*\(|\.send\s*\(|\.transfer\s*\(").unwrap()
});

static NON_REENTRANT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"nonReentrant|ReentrancyGuard|mutex|locked").unwrap()
});

static STATE_CHANGE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\w+\s*\[[^\]]*\]\s*=\s*[^=]|delete\s+\w+").unwrap()
});

#[derive(Default)]
pub struct ReentrancyRule;

/// Extract function body by counting braces
fn extract_function_body(source: &str, start: usize) -> Option<(usize, &str)> {
    let src = &source[start..];
    let mut brace_count = 0;
    let mut in_body = false;
    let mut body_start = 0;

    for (i, ch) in src.char_indices() {
        if ch == '{' {
            if !in_body {
                body_start = i + 1;
                in_body = true;
            }
            brace_count += 1;
        } else if ch == '}' {
            brace_count -= 1;
            if brace_count == 0 && in_body {
                return Some((start + body_start, &src[body_start..i]));
            }
        }
    }
    None
}

impl Rule for ReentrancyRule {
    fn id(&self) -> &'static str {
        "reentrancy"
    }

    fn name(&self) -> &'static str {
        "Reentrancy Vulnerability"
    }

    fn description(&self) -> &'static str {
        "Detects functions with external calls that modify state afterwards, \
         potentially allowing reentrancy attacks. The checks-effects-interactions \
         pattern should be followed: perform all state changes before external calls."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn swc_id(&self) -> Option<&'static str> {
        Some("SWC-107")
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-841")
    }

    fn analyze(&self, ctx: &RuleContext) -> Vec<Finding> {
        let source = ctx.source.as_ref();
        let mut findings = Vec::new();

        for func_cap in FUNC_HEADER_RE.captures_iter(source) {
            let func_name = func_cap.get(1).map(|m| m.as_str()).unwrap_or("<unknown>");
            let func_start = func_cap.get(0).map(|m| m.start()).unwrap_or(0);
            let header = func_cap.get(0).map(|m| m.as_str()).unwrap_or("");

            // Skip if protected by reentrancy guard in header
            if NON_REENTRANT_RE.is_match(header) {
                continue;
            }

            // Extract function body
            let Some((_body_start, body)) = extract_function_body(source, func_start) else {
                continue;
            };

            // Find external calls in the body
            if let Some(call_match) = EXTERNAL_CALL_RE.find(body) {
                let call_pos = call_match.start();
                let after_call = &body[call_match.end()..];

                // Check for state changes after the external call
                if STATE_CHANGE_RE.is_match(after_call) {
                    let abs_pos = func_start + call_pos;

                    findings.push(
                        Finding::new(self.id(), format!("Potential reentrancy in `{}`", func_name))
                            .with_description(format!(
                                "Function `{}` contains an external call followed by state modifications. \
                                 This pattern is vulnerable to reentrancy attacks where the called contract \
                                 can re-enter this function before state updates complete.",
                                func_name
                            ))
                            .with_severity(Severity::High)
                            .with_confidence(Confidence::High)
                            .with_location(ctx.make_span(abs_pos, abs_pos + call_match.as_str().len()))
                            .with_suggestion(
                                "Apply the checks-effects-interactions pattern: update state before \
                                 making external calls. Alternatively, use a reentrancy guard modifier."
                            )
                            .with_trace(vec![
                                format!("Function `{}` is public/external", func_name),
                                format!("External call found: {}", call_match.as_str().trim()),
                                "State modification occurs after external call".into(),
                                "No reentrancy guard detected".into(),
                            ])
                            .with_swc("SWC-107")
                            .with_cwe("CWE-841"),
                    );
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auditforge_core::{load_default_config, AstNode};
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
    fn detects_reentrancy() {
        let source = r#"
contract Vulnerable {
    mapping(address => uint) balances;
    
    function withdraw() external {
        uint amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = ReentrancyRule;
        let findings = rule.analyze(&ctx);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("withdraw"));
    }

    #[test]
    fn ignores_protected_functions() {
        let source = r#"
contract Safe {
    mapping(address => uint) balances;
    
    function withdraw() external nonReentrant {
        uint amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = ReentrancyRule;
        let findings = rule.analyze(&ctx);

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn ignores_cei_pattern() {
        let source = r#"
contract Safe {
    mapping(address => uint) balances;
    
    function withdraw() external {
        uint amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = ReentrancyRule;
        let findings = rule.analyze(&ctx);

        assert_eq!(findings.len(), 0);
    }
}
