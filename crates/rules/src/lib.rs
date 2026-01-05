//! AuditForge Rules — Built-in security rules for smart contract analysis.
//!
//! This crate provides a collection of security rules targeting common
//! vulnerabilities in Solidity and other smart contract languages.

mod access_control;
mod delegatecall;
mod overflow;
mod reentrancy;
mod tx_origin;
mod unchecked_return;
mod uninitialized_storage;

pub use access_control::AccessControlRule;
pub use delegatecall::DelegatecallRule;
pub use overflow::OverflowRule;
pub use reentrancy::ReentrancyRule;
pub use tx_origin::TxOriginRule;
pub use unchecked_return::UncheckedReturnRule;
pub use uninitialized_storage::UninitializedStorageRule;

use auditforge_core::RuleRegistry;
use std::sync::Arc;

/// Register all built-in rules with the registry.
pub fn register_all(registry: &RuleRegistry) {
    registry.register(Arc::new(ReentrancyRule));
    registry.register(Arc::new(DelegatecallRule));
    registry.register(Arc::new(AccessControlRule));
    registry.register(Arc::new(UncheckedReturnRule));
    registry.register(Arc::new(TxOriginRule));
    registry.register(Arc::new(OverflowRule));
    registry.register(Arc::new(UninitializedStorageRule));
}

/// Get a list of all available rule IDs and their descriptions.
pub fn list_rules() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("reentrancy", "Reentrancy Vulnerability", "SWC-107"),
        ("delegatecall", "Unsafe Delegatecall", "SWC-112"),
        ("access-control", "Missing Access Control", "SWC-105"),
        ("unchecked-return", "Unchecked Call Return Value", "SWC-104"),
        ("tx-origin", "tx.origin Authentication", "SWC-115"),
        ("overflow", "Integer Overflow/Underflow", "SWC-101"),
        ("uninitialized-storage", "Uninitialized Storage Pointer", "SWC-109"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_all_rules() {
        let registry = RuleRegistry::new();
        register_all(&registry);
        
        let rules = registry.all();
        assert_eq!(rules.len(), 7);
    }

    #[test]
    fn list_rules_matches_registry() {
        let registry = RuleRegistry::new();
        register_all(&registry);
        
        let list = list_rules();
        let ids: Vec<_> = registry.ids();
        
        for (id, _, _) in &list {
            assert!(ids.contains(&id.to_string()), "Missing rule: {}", id);
        }
    }
}
