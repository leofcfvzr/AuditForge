# Contributing to AuditForge

Thank you for your interest in contributing to AuditForge! This document provides guidelines and information for contributors.

## 🚀 Getting Started

1. **Fork & Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/auditforge
   cd auditforge
   ```

2. **Install Dependencies**
   - Rust 1.75+ (`rustup update stable`)
   - solc (`npm install -g solc`)

3. **Build & Test**
   ```bash
   cargo build
   cargo test --all
   ```

## 📝 Development Workflow

### Branch Naming

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
```
feat(rules): add unchecked-external-call rule
fix(parser): handle multi-file projects
docs(readme): update installation instructions
```

### Pull Request Process

1. Create a feature branch from `main`
2. Make your changes
3. Add/update tests
4. Run `cargo fmt` and `cargo clippy`
5. Update documentation if needed
6. Submit PR with clear description

## 🛡️ Adding New Rules

### Rule Structure

1. Create `crates/rules/src/my_rule.rs`:

```rust
use auditforge_core::{Confidence, Finding, Rule, RuleContext, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

static PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"your_pattern_here").unwrap()
});

#[derive(Default)]
pub struct MyRule;

impl Rule for MyRule {
    fn id(&self) -> &'static str {
        "my-rule"
    }

    fn name(&self) -> &'static str {
        "My Rule Name"
    }

    fn description(&self) -> &'static str {
        "Detailed description of what this rule detects and why it matters."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn swc_id(&self) -> Option<&'static str> {
        Some("SWC-XXX")
    }

    fn cwe_id(&self) -> Option<&'static str> {
        Some("CWE-XXX")
    }

    fn analyze(&self, ctx: &RuleContext) -> Vec<Finding> {
        let source = ctx.source.as_ref();
        let mut findings = Vec::new();

        for cap in PATTERN.find_iter(source) {
            findings.push(
                Finding::new(self.id(), "Issue Title")
                    .with_description("Detailed description")
                    .with_severity(self.severity())
                    .with_confidence(self.confidence())
                    .with_location(ctx.make_span(cap.start(), cap.end()))
                    .with_suggestion("How to fix this issue")
                    .with_swc("SWC-XXX"),
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
    fn detects_vulnerability() {
        let source = r#"
            // Your test contract here
        "#;
        let ctx = make_ctx(source);
        let rule = MyRule;
        let findings = rule.analyze(&ctx);
        
        assert!(!findings.is_empty());
    }

    #[test]
    fn ignores_safe_code() {
        let source = r#"
            // Safe code that shouldn't trigger
        "#;
        let ctx = make_ctx(source);
        let rule = MyRule;
        let findings = rule.analyze(&ctx);
        
        assert!(findings.is_empty());
    }
}
```

2. **Register the rule** in `crates/rules/src/lib.rs`:

```rust
mod my_rule;
pub use my_rule::MyRule;

pub fn register_all(registry: &RuleRegistry) {
    // ... existing rules
    registry.register(Arc::new(MyRule));
}
```

3. **Add knowledge base entry** in `crates/knowledge_base/src/lib.rs`

### Rule Guidelines

- **Minimize false positives**: Prefer precision over recall
- **Provide actionable suggestions**: Tell users how to fix issues
- **Include trace information**: Help users understand the detection logic
- **Reference standards**: Link to SWC/CWE when applicable
- **Write comprehensive tests**: Cover vulnerable AND safe code

## 🧪 Testing

### Test Categories

- **Unit tests**: In each module (`#[cfg(test)]`)
- **Integration tests**: In `tests/` directory
- **Property tests**: Use `proptest` for fuzzing

### Running Tests

```bash
# All tests
cargo test --all

# Specific crate
cargo test -p auditforge-rules

# With output
cargo test -- --nocapture

# Single test
cargo test test_name
```

## 📊 Code Quality

### Formatting

```bash
cargo fmt --all
```

### Linting

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

### Documentation

```bash
cargo doc --no-deps --open
```

## 🐛 Bug Reports

Include:
1. AuditForge version
2. Solidity version
3. Minimal reproducing contract
4. Expected vs actual behavior
5. Full error output

## 💡 Feature Requests

Open an issue with:
1. Use case description
2. Proposed solution
3. Alternatives considered

## 📜 Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Questions? Open an issue or reach out to the maintainers. Thank you for contributing! 🙏

