//! AuditForge Knowledge Base — Rule metadata and vulnerability information.
//!
//! This crate provides a knowledge base of security rules with detailed
//! descriptions, references, and remediation guidance.

use anyhow::Result;
use auditforge_core::{Confidence, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Knowledge base entry for a security rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnowledgeEntry {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    #[serde(default)]
    pub swc_id: Option<String>,
    #[serde(default)]
    pub cwe_id: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub examples: Vec<CodeExample>,
}

/// Code example for a vulnerability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeExample {
    pub title: String,
    pub vulnerable: String,
    pub fixed: String,
}

/// Knowledge base with all rule entries.
#[derive(Clone, Debug, Default)]
pub struct KnowledgeBase {
    entries: HashMap<String, KnowledgeEntry>,
}

impl KnowledgeBase {
    /// Create a new empty knowledge base.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load knowledge base from YAML content.
    pub fn load_yaml(content: &str) -> Result<Self> {
        let entries: Vec<KnowledgeEntry> = serde_yaml::from_str(content)?;
        let mut kb = Self::new();
        for entry in entries {
            kb.entries.insert(entry.rule_id.clone(), entry);
        }
        Ok(kb)
    }

    /// Load the built-in knowledge base.
    pub fn load_builtin() -> Self {
        Self::load_yaml(BUILTIN_KNOWLEDGE_BASE)
            .expect("Built-in knowledge base should be valid")
    }

    /// Get entry by rule ID.
    pub fn get(&self, rule_id: &str) -> Option<&KnowledgeEntry> {
        self.entries.get(rule_id)
    }

    /// Get all entries.
    pub fn all(&self) -> impl Iterator<Item = &KnowledgeEntry> {
        self.entries.values()
    }
}

/// Built-in knowledge base YAML.
pub const BUILTIN_KNOWLEDGE_BASE: &str = r#"
- rule_id: reentrancy
  title: Reentrancy Vulnerability
  description: |
    A reentrancy attack occurs when a contract makes an external call to another
    untrusted contract before updating its own state. The called contract can then
    call back into the original contract before the first execution is complete,
    potentially draining funds or corrupting state.
  severity: high
  confidence: high
  swc_id: SWC-107
  cwe_id: CWE-841
  references:
    - https://swcregistry.io/docs/SWC-107
    - https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/
  remediation: |
    1. Use the Checks-Effects-Interactions pattern: perform all state changes
       before making external calls.
    2. Use a reentrancy guard (mutex) like OpenZeppelin's ReentrancyGuard.
    3. Consider using pull-payment patterns instead of push payments.
  examples:
    - title: Classic Reentrancy
      vulnerable: |
        function withdraw() external {
            uint256 amount = balances[msg.sender];
            (bool ok,) = msg.sender.call{value: amount}("");
            require(ok);
            balances[msg.sender] = 0;  // State change after call!
        }
      fixed: |
        function withdraw() external nonReentrant {
            uint256 amount = balances[msg.sender];
            balances[msg.sender] = 0;  // State change before call
            (bool ok,) = msg.sender.call{value: amount}("");
            require(ok);
        }

- rule_id: delegatecall
  title: Unsafe Delegatecall
  description: |
    Delegatecall executes code from another contract in the context of the
    calling contract. This means the called code has full access to the caller's
    storage and can modify it. If the target address can be controlled by an
    attacker, they can execute arbitrary code.
  severity: critical
  confidence: medium
  swc_id: SWC-112
  cwe_id: CWE-829
  references:
    - https://swcregistry.io/docs/SWC-112
    - https://blog.openzeppelin.com/on-the-parity-wallet-multisig-hack-405a8c12e8f7/
  remediation: |
    1. Never allow user input to control delegatecall targets.
    2. Use immutable implementation addresses or trusted registries.
    3. For proxy patterns, use established patterns like OpenZeppelin's
       TransparentUpgradeableProxy or UUPS.
  examples:
    - title: Arbitrary Delegatecall
      vulnerable: |
        function execute(address target, bytes calldata data) external {
            target.delegatecall(data);  // Anyone can call any contract!
        }
      fixed: |
        function execute(bytes calldata data) external onlyOwner {
            implementation.delegatecall(data);  // Fixed target, access control
        }

- rule_id: access-control
  title: Missing Access Control
  description: |
    Privileged functions that modify critical state or transfer funds must have
    proper access controls to prevent unauthorized users from calling them.
    Missing access control is one of the most common smart contract vulnerabilities.
  severity: high
  confidence: high
  swc_id: SWC-105
  cwe_id: CWE-284
  references:
    - https://swcregistry.io/docs/SWC-105
    - https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/access-control/
  remediation: |
    1. Use access control modifiers like onlyOwner for privileged functions.
    2. Consider role-based access control (RBAC) for complex permission systems.
    3. Use OpenZeppelin's Ownable or AccessControl contracts.
  examples:
    - title: Unprotected Setter
      vulnerable: |
        function setOwner(address newOwner) external {
            owner = newOwner;  // Anyone can take ownership!
        }
      fixed: |
        function setOwner(address newOwner) external onlyOwner {
            owner = newOwner;
        }

- rule_id: unchecked-return
  title: Unchecked Call Return Value
  description: |
    Low-level calls (call, delegatecall, send) return a boolean indicating success
    or failure. If this return value is not checked, failed calls will silently
    continue execution, potentially leading to loss of funds or incorrect state.
  severity: medium
  confidence: high
  swc_id: SWC-104
  cwe_id: CWE-252
  references:
    - https://swcregistry.io/docs/SWC-104
  remediation: |
    1. Always check return values: require(success, "call failed")
    2. Use OpenZeppelin's Address.sendValue() for ETH transfers
    3. Consider using transfer() for simple ETH transfers (though be aware of
       gas limitations)
  examples:
    - title: Unchecked Send
      vulnerable: |
        function withdraw() external {
            payable(msg.sender).send(balance);  // Return value ignored!
        }
      fixed: |
        function withdraw() external {
            (bool success,) = payable(msg.sender).call{value: balance}("");
            require(success, "Transfer failed");
        }

- rule_id: tx-origin
  title: tx.origin Authentication
  description: |
    Using tx.origin for authorization is vulnerable to phishing attacks. A malicious
    contract can trick a user into calling it, then make calls to the victim contract.
    Since tx.origin is the original external account, authorization checks will pass.
  severity: high
  confidence: high
  swc_id: SWC-115
  cwe_id: CWE-477
  references:
    - https://swcregistry.io/docs/SWC-115
    - https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/tx-origin/
  remediation: |
    Use msg.sender instead of tx.origin for authorization. msg.sender is always
    the immediate caller, which prevents phishing attacks through intermediate
    contracts.
  examples:
    - title: tx.origin Phishing
      vulnerable: |
        function withdraw() external {
            require(tx.origin == owner);  // Vulnerable to phishing!
            payable(msg.sender).transfer(balance);
        }
      fixed: |
        function withdraw() external {
            require(msg.sender == owner);  // msg.sender is safe
            payable(msg.sender).transfer(balance);
        }

- rule_id: overflow
  title: Integer Overflow/Underflow
  description: |
    In Solidity versions before 0.8.0, arithmetic operations can overflow or
    underflow without reverting. This can lead to unexpected behavior, such as
    bypassing balance checks or minting excessive tokens.
  severity: high
  confidence: medium
  swc_id: SWC-101
  cwe_id: CWE-190
  references:
    - https://swcregistry.io/docs/SWC-101
    - https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/integer-overflow-and-underflow/
  remediation: |
    1. Upgrade to Solidity 0.8.0+ which has built-in overflow checks.
    2. For older versions, use SafeMath library for all arithmetic.
    3. Validate inputs to prevent overflow conditions.
  examples:
    - title: Balance Underflow
      vulnerable: |
        // Solidity < 0.8.0
        function transfer(address to, uint256 amount) external {
            balances[msg.sender] -= amount;  // Can underflow!
            balances[to] += amount;
        }
      fixed: |
        // Solidity >= 0.8.0 (automatic checks)
        function transfer(address to, uint256 amount) external {
            balances[msg.sender] -= amount;  // Reverts on underflow
            balances[to] += amount;
        }

- rule_id: uninitialized-storage
  title: Uninitialized Storage Pointer
  description: |
    Local storage variables that are not initialized point to storage slot 0 by
    default. Writing to such variables can overwrite the first state variable
    in the contract, leading to unexpected behavior or security issues.
  severity: high
  confidence: high
  swc_id: SWC-109
  cwe_id: CWE-824
  references:
    - https://swcregistry.io/docs/SWC-109
  remediation: |
    1. Always initialize storage pointers to a specific storage location.
    2. Use memory instead of storage if a copy is acceptable.
    3. Modern Solidity versions (0.5.0+) produce a compiler error for this.
  examples:
    - title: Storage Pointer Overlap
      vulnerable: |
        // Solidity < 0.5.0
        function bad() external {
            User storage user;  // Points to slot 0!
            user.id = 1;  // Overwrites first state variable
        }
      fixed: |
        function good(uint256 index) external {
            User storage user = users[index];  // Proper initialization
            user.id = 1;
        }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_builtin_kb() {
        let kb = KnowledgeBase::load_builtin();
        assert!(kb.get("reentrancy").is_some());
        assert!(kb.get("delegatecall").is_some());
        assert!(kb.get("access-control").is_some());
    }

    #[test]
    fn entry_has_expected_fields() {
        let kb = KnowledgeBase::load_builtin();
        let entry = kb.get("reentrancy").unwrap();
        
        assert_eq!(entry.swc_id, Some("SWC-107".to_string()));
        assert!(!entry.references.is_empty());
        assert!(entry.remediation.is_some());
        assert!(!entry.examples.is_empty());
    }

    #[test]
    fn loads_custom_yaml() {
        let yaml = r#"
- rule_id: custom
  title: Custom Rule
  description: A custom rule
  severity: medium
  confidence: low
"#;
        let kb = KnowledgeBase::load_yaml(yaml).unwrap();
        assert!(kb.get("custom").is_some());
    }
}
