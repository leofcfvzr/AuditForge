//! tx.origin authentication vulnerability detection (SWC-115).
//!
//! Detects usage of tx.origin for authorization, which is vulnerable to
//! phishing attacks where a malicious contract can trick users into
//! authorizing transactions.

use auditforge_core::{Confidence, Finding, Rule, RuleContext, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

// Match tx.origin used in require/if conditions
static TX_ORIGIN_AUTH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:require|if|assert)\s*\([^)]*tx\.origin[^)]*\)").unwrap()
});

// Match tx.origin comparisons
static TX_ORIGIN_COMPARE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"tx\.origin\s*==|==\s*tx\.origin").unwrap()
});

// Match tx.origin assignments
static TX_ORIGIN_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\w+\s*=\s*tx\.origin").unwrap()
});

#[derive(Default)]
pub struct TxOriginRule;

impl Rule for TxOriginRule {
    fn id(&self) -> &'static str {
        "tx-origin"
    }

    fn name(&self) -> &'static str {
        "tx.origin Authentication"
    }

    fn description(&self) -> &'static str {
        "Detects usage of tx.origin for authorization. Unlike msg.sender, tx.origin \
         refers to the original external account that initiated the transaction chain. \
         This makes it vulnerable to phishing attacks where a malicious contract tricks \
         users into calling it, then calls the victim contract with the user's tx.origin."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn swc_id(&self) -> Option<&'static str> {
        Some("SWC-115")
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-477")
    }

    fn analyze(&self, ctx: &RuleContext) -> Vec<Finding> {
        let source = ctx.source.as_ref();
        let mut findings = Vec::new();

        // Check for tx.origin in authorization patterns
        for cap in TX_ORIGIN_AUTH_RE.find_iter(source) {
            let match_start = cap.start();
            let match_str = cap.as_str();

            // If it's comparing tx.origin, it's likely for auth
            if TX_ORIGIN_COMPARE_RE.is_match(match_str) {
                findings.push(
                    Finding::new(self.id(), "tx.origin used for authentication")
                        .with_description(
                            "tx.origin is used for authorization. A phishing contract can trick \
                             users into calling it, then forward the call to this contract. \
                             The check will pass because tx.origin is the victim's address."
                        )
                        .with_severity(Severity::High)
                        .with_confidence(Confidence::High)
                        .with_location(ctx.make_span(match_start, match_start + match_str.len()))
                        .with_suggestion(
                            "Use msg.sender instead of tx.origin for authorization. \
                             msg.sender is always the immediate caller, preventing phishing attacks."
                        )
                        .with_swc("SWC-115")
                        .with_cwe("CWE-477"),
                );
            }
        }

        // Also check for tx.origin being stored (often used later for auth)
        for cap in TX_ORIGIN_ASSIGN_RE.find_iter(source) {
            let match_start = cap.start();
            let match_str = cap.as_str();

            // Skip if it's owner = msg.sender pattern (common and safe)
            if match_str.contains("msg.sender") {
                continue;
            }

            findings.push(
                Finding::new(self.id(), "tx.origin assigned to variable")
                    .with_description(
                        "tx.origin is stored in a variable. If this value is later used \
                         for authorization, it could be vulnerable to phishing attacks."
                    )
                    .with_severity(Severity::Medium)
                    .with_confidence(Confidence::Medium)
                    .with_location(ctx.make_span(match_start, match_start + match_str.len()))
                    .with_suggestion(
                        "Consider using msg.sender if this value will be used for authorization."
                    )
                    .with_swc("SWC-115")
                    .with_cwe("CWE-477"),
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
    fn detects_tx_origin_auth() {
        let source = r#"
contract Wallet {
    address owner;
    
    function withdraw() external {
        require(tx.origin == owner, "not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = TxOriginRule;
        let findings = rule.analyze(&ctx);
        
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn no_findings_for_msg_sender() {
        let source = r#"
contract Wallet {
    address owner;
    
    function withdraw() external {
        require(msg.sender == owner, "not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}
"#;
        let ctx = make_ctx(source);
        let rule = TxOriginRule;
        let findings = rule.analyze(&ctx);
        
        assert_eq!(findings.len(), 0);
    }
}

