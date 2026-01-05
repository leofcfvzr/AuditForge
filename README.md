# 🔐 AuditForge

**Static security analyzer for Web3 smart contracts**

[![CI](https://github.com/example/auditforge/actions/workflows/ci.yml/badge.svg)](https://github.com/example/auditforge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org/)

AuditForge is a fast, extensible static analysis tool for detecting security vulnerabilities in Solidity smart contracts. Built in Rust for performance and reliability.

## ✨ Features

- **7 Built-in Security Rules** targeting critical vulnerabilities (SWC registry aligned)
- **Multiple Output Formats**: Text (colored), JSON, SARIF (for CI/CD integration)
- **Configurable**: TOML config, CLI overrides, per-rule settings
- **Ignore Directives**: Skip false positives with `// auditforge-ignore`
- **Fast**: Parallel analysis with Rayon, efficient regex-based detection
- **Extensible**: Modular rule architecture for custom rules

## 🚀 Quick Start

### Installation

```bash
# From source
git clone https://github.com/example/auditforge
cd auditforge
cargo install --path crates/cli

# Requires solc in PATH
# Install via: npm install -g solc
```

### Basic Usage

```bash
# Scan a single file
auditforge scan --path contracts/MyContract.sol

# Scan a directory recursively
auditforge scan --path contracts/ --recursive

# Output as JSON
auditforge scan --path contracts/ --format json

# Output as SARIF (for GitHub Actions, etc.)
auditforge scan --path contracts/ --format sarif > results.sarif

# Filter by severity
auditforge scan --path contracts/ --min-severity high

# Run specific rules only
auditforge scan --path contracts/ --only reentrancy,delegatecall

# Exclude rules
auditforge scan --path contracts/ --exclude overflow

# Use config file
auditforge scan --path contracts/ --config auditforge.toml

# Fail CI if issues found
auditforge scan --path contracts/ --fail-on-findings
```

### List Available Rules

```bash
auditforge rules
```

### Initialize Configuration

```bash
auditforge init
```

## 🛡️ Security Rules

| Rule ID | Name | SWC | Severity | Description |
|---------|------|-----|----------|-------------|
| `reentrancy` | Reentrancy | SWC-107 | High | External calls before state updates |
| `delegatecall` | Unsafe Delegatecall | SWC-112 | Critical | Uncontrolled delegatecall targets |
| `access-control` | Missing Access Control | SWC-105 | High | Privileged functions without auth |
| `unchecked-return` | Unchecked Return | SWC-104 | Medium | Ignored call/send return values |
| `tx-origin` | tx.origin Auth | SWC-115 | High | Using tx.origin for authorization |
| `overflow` | Integer Overflow | SWC-101 | High | Arithmetic overflow/underflow |
| `uninitialized-storage` | Uninitialized Storage | SWC-109 | High | Uninitialized storage pointers |

## ⚙️ Configuration

Create `auditforge.toml` in your project root:

```toml
# Minimum confidence level (low, medium, high)
min_confidence = "low"

# Minimum severity level (info, low, medium, high, critical)
min_severity = "info"

# Paths to ignore (glob patterns)
ignore_paths = [
    "**/node_modules/**",
    "**/test/**",
]

# Rules to run exclusively (empty = all)
only_rules = []

# Rules to exclude
exclude_rules = []

# Per-rule configuration
[rules.reentrancy]
enabled = true

[rules.overflow]
enabled = true
min_confidence = "high"
```

## 🔇 Suppressing Findings

Use comments to suppress specific findings:

```solidity
// Ignore all rules on next line
// auditforge-ignore
balances[msg.sender] = 0;

// Ignore specific rule
// auditforge-ignore reentrancy
(bool ok,) = msg.sender.call{value: amount}("");

// Ignore with reason
// auditforge-ignore reentrancy -- protected by mutex in parent contract
(bool ok,) = msg.sender.call{value: amount}("");
```

## 🏗️ Project Structure

```
auditforge/
├── crates/
│   ├── core/           # AST model, rule trait, registry
│   ├── solc-parser/    # Solidity parser (solc wrapper)
│   ├── rules/          # Built-in security rules
│   ├── knowledge_base/ # Rule documentation & examples
│   └── cli/            # Command-line interface
├── examples/           # Sample vulnerable contracts
└── .github/workflows/  # CI/CD configuration
```

## 🔧 Development

### Prerequisites

- Rust 1.75+
- solc (Solidity compiler)

### Building

```bash
cargo build --release
```

### Testing

```bash
# Run all tests
cargo test --all

# Run with coverage
cargo tarpaulin --all
```

### Adding a New Rule

1. Create `crates/rules/src/my_rule.rs`:

```rust
use auditforge_core::{Confidence, Finding, Rule, RuleContext, Severity};

#[derive(Default)]
pub struct MyRule;

impl Rule for MyRule {
    fn id(&self) -> &'static str { "my-rule" }
    fn name(&self) -> &'static str { "My Rule" }
    fn description(&self) -> &'static str { "Description of what this rule detects" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn confidence(&self) -> Confidence { Confidence::High }
    fn swc_id(&self) -> Option<&'static str> { Some("SWC-XXX") }
    
    fn analyze(&self, ctx: &RuleContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Your detection logic here
        findings
    }
}
```

2. Register in `crates/rules/src/lib.rs`
3. Add to knowledge base in `crates/knowledge_base/src/lib.rs`

## 📊 CI/CD Integration

### GitHub Actions

```yaml
- name: Run AuditForge
  run: |
    auditforge scan --path contracts/ --format sarif --output results.sarif --fail-on-findings

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  script:
    - auditforge scan --path contracts/ --format json --fail-on-findings
  artifacts:
    reports:
      sast: results.json
```

## 📈 Roadmap

- [ ] Support for Rust smart contracts (Anchor, ink!)
- [ ] Symbolic execution integration
- [ ] Data flow analysis
- [ ] Custom rule plugins (WASM)
- [ ] VS Code extension
- [ ] Web dashboard

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) first.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `cargo test --all`
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔗 References

- [SWC Registry](https://swcregistry.io/) - Smart Contract Weakness Classification
- [Consensys Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)

---

Built with ❤️ for the Web3 security community
# AuditForge
