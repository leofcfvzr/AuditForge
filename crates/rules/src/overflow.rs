//! Integer overflow/underflow detection (SWC-101).
//!
//! Detects potential integer overflow/underflow in Solidity versions < 0.8.0
//! where arithmetic operations don't automatically check for overflow.

use auditforge_core::{Confidence, Finding, Rule, RuleContext, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

// Match pragma solidity version
static PRAGMA_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"pragma\s+solidity\s*[\^>=<]*\s*(\d+)\.(\d+)\.?(\d+)?").unwrap()
});

// Match arithmetic operations (including compound assignments like += -= *= /=)
static ARITH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[+\-*/]=|\w+\s*[+\-*/]\s*\w+|\+\+\w+|\-\-\w+|\w+\+\+|\w+\-\-").unwrap()
});

// Match SafeMath usage
static SAFEMATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"using\s+SafeMath|\.add\(|\.sub\(|\.mul\(|\.div\(").unwrap()
});

// Match unchecked blocks (Solidity 0.8+)
#[allow(dead_code)]
static UNCHECKED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"unchecked\s*\{").unwrap()
});

#[derive(Default)]
pub struct OverflowRule;

impl Rule for OverflowRule {
    fn id(&self) -> &'static str {
        "overflow"
    }

    fn name(&self) -> &'static str {
        "Integer Overflow/Underflow"
    }

    fn description(&self) -> &'static str {
        "Detects potential integer overflow/underflow vulnerabilities. \
         In Solidity < 0.8.0, arithmetic operations can overflow/underflow \
         silently. In >= 0.8.0, unchecked blocks bypass overflow protection."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }

    fn swc_id(&self) -> Option<&'static str> {
        Some("SWC-101")
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-190")
    }

    fn analyze(&self, ctx: &RuleContext) -> Vec<Finding> {
        let source = ctx.source.as_ref();
        let mut findings = Vec::new();

        // Determine Solidity version
        let (major, minor) = PRAGMA_RE
            .captures(source)
            .map(|cap| {
                let major = cap.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
                let minor = cap.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
                (major, minor)
            })
            .unwrap_or((0, 8)); // Assume 0.8+ if not specified

        let is_pre_08 = major == 0 && minor < 8;
        let uses_safemath = SAFEMATH_RE.is_match(source);

        if is_pre_08 && !uses_safemath {
            // Pre-0.8 without SafeMath: flag all arithmetic
            for arith_match in ARITH_RE.find_iter(source) {
                let match_start = arith_match.start();
                let match_str = arith_match.as_str();

                // Skip if it's in a comment
                let line_start = source[..match_start].rfind('\n').unwrap_or(0);
                let line = &source[line_start..match_start];
                if line.contains("//") {
                    continue;
                }

                findings.push(
                    Finding::new(self.id(), "Unprotected arithmetic operation")
                        .with_description(format!(
                            "Arithmetic operation `{}` in Solidity {} without SafeMath. \
                             This can overflow/underflow silently, leading to unexpected behavior.",
                            match_str.trim(),
                            format!("{}.{}", major, minor)
                        ))
                        .with_severity(Severity::High)
                        .with_confidence(Confidence::Medium)
                        .with_location(ctx.make_span(match_start, match_start + match_str.len()))
                        .with_suggestion(
                            "Use SafeMath library for arithmetic operations, or upgrade to Solidity >= 0.8.0 \
                             which has built-in overflow checks."
                        )
                        .with_swc("SWC-101")
                        .with_cwe("CWE-190"),
                );
            }
        } else {
            // Solidity 0.8+: check for unchecked blocks
            let mut unchecked_start = None;
            let mut brace_count = 0;

            for (i, ch) in source.char_indices() {
                if source[i..].starts_with("unchecked") {
                    // Find the opening brace
                    if let Some(brace_pos) = source[i..].find('{') {
                        unchecked_start = Some(i + brace_pos);
                        brace_count = 1;
                    }
                }

                if unchecked_start.is_some() {
                    if ch == '{' && !source[i..].starts_with("unchecked") {
                        brace_count += 1;
                    } else if ch == '}' {
                        brace_count -= 1;
                        if brace_count == 0 {
                            // Found end of unchecked block
                            let start = unchecked_start.unwrap();
                            let block = &source[start..=i];

                            // Check for arithmetic in unchecked block
                            if ARITH_RE.is_match(block) {
                                findings.push(
                                    Finding::new(self.id(), "Arithmetic in unchecked block")
                                        .with_description(
                                            "Arithmetic operations in unchecked block bypass Solidity 0.8+ \
                                             overflow protection. Ensure this is intentional and inputs are validated."
                                        )
                                        .with_severity(Severity::Medium)
                                        .with_confidence(Confidence::Low)
                                        .with_location(ctx.make_span(start - 9, i + 1)) // Include "unchecked"
                                        .with_suggestion(
                                            "Only use unchecked blocks when overflow is mathematically impossible \
                                             or when gas optimization is critical and inputs are validated."
                                        )
                                        .with_swc("SWC-101")
                                        .with_cwe("CWE-190"),
                                );
                            }

                            unchecked_start = None;
                        }
                    }
                }
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
    fn detects_pre_08_overflow() {
        let source = r#"
pragma solidity ^0.7.0;

contract Token {
    mapping(address => uint256) balances;
    
    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = OverflowRule;
        let findings = rule.analyze(&ctx);
        
        assert!(!findings.is_empty());
    }

    #[test]
    fn ignores_safemath() {
        let source = r#"
pragma solidity ^0.7.0;

import "@openzeppelin/contracts/math/SafeMath.sol";

contract Token {
    using SafeMath for uint256;
    mapping(address => uint256) balances;
    
    function transfer(address to, uint256 amount) external {
        balances[msg.sender] = balances[msg.sender].sub(amount);
        balances[to] = balances[to].add(amount);
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = OverflowRule;
        let findings = rule.analyze(&ctx);
        
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_unchecked_in_08() {
        let source = r#"
pragma solidity ^0.8.0;

contract Counter {
    uint256 count;
    
    function increment() external {
        unchecked {
            count++;
        }
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = OverflowRule;
        let findings = rule.analyze(&ctx);
        
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }
}

