//! AuditForge Core — AST model, rule trait, registry, and config helpers.

use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

// ============================================================================
// Source Location
// ============================================================================

/// Source code span with line/column info.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub file: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

impl Span {
    pub fn new(start: usize, end: usize, file: impl Into<String>) -> Self {
        Self {
            start,
            end,
            file: file.into(),
            line: None,
            column: None,
        }
    }

    pub fn with_line_col(mut self, line: usize, column: usize) -> Self {
        self.line = Some(line);
        self.column = Some(column);
        self
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let (Some(line), Some(col)) = (self.line, self.column) {
            write!(f, "{}:{}:{}", self.file, line, col)
        } else {
            write!(f, "{}:{}-{}", self.file, self.start, self.end)
        }
    }
}

// ============================================================================
// AST Model
// ============================================================================

/// Unified AST node for all supported languages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AstNode {
    pub kind: String,
    pub name: Option<String>,
    pub span: Option<Span>,
    pub attributes: HashMap<String, String>,
    pub children: Vec<AstNode>,
}

impl AstNode {
    pub fn new(kind: impl Into<String>, span: Option<Span>, children: Vec<AstNode>) -> Self {
        Self {
            kind: kind.into(),
            name: None,
            span,
            attributes: HashMap::new(),
            children,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Recursively find all nodes matching a predicate.
    pub fn find_all<F>(&self, predicate: F) -> Vec<&AstNode>
    where
        F: Fn(&AstNode) -> bool + Copy,
    {
        let mut result = Vec::new();
        if predicate(self) {
            result.push(self);
        }
        for child in &self.children {
            result.extend(child.find_all(predicate));
        }
        result
    }

    /// Find first node matching predicate.
    pub fn find_first<F>(&self, predicate: F) -> Option<&AstNode>
    where
        F: Fn(&AstNode) -> bool + Copy,
    {
        if predicate(self) {
            return Some(self);
        }
        for child in &self.children {
            if let Some(found) = child.find_first(predicate) {
                return Some(found);
            }
        }
        None
    }

    /// Get attribute value.
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(String::as_str)
    }
}

// ============================================================================
// Severity & Confidence
// ============================================================================

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low = 0,
    Medium = 1,
    High = 2,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Info => write!(f, "Info"),
        }
    }
}

// ============================================================================
// Finding
// ============================================================================

/// A detected vulnerability or issue.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub location: Option<Span>,
    pub suggestion: Option<String>,
    pub trace: Option<Vec<String>>,
    pub swc_id: Option<String>,
    pub cwe_id: Option<String>,
}

impl Finding {
    pub fn new(rule_id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            rule_id: rule_id.into(),
            title: title.into(),
            description: String::new(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            location: None,
            suggestion: None,
            trace: None,
            swc_id: None,
            cwe_id: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_location(mut self, location: Span) -> Self {
        self.location = Some(location);
        self
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    pub fn with_trace(mut self, trace: Vec<String>) -> Self {
        self.trace = Some(trace);
        self
    }

    pub fn with_swc(mut self, swc_id: impl Into<String>) -> Self {
        self.swc_id = Some(swc_id.into());
        self
    }

    pub fn with_cwe(mut self, cwe_id: impl Into<String>) -> Self {
        self.cwe_id = Some(cwe_id.into());
        self
    }
}

// ============================================================================
// Configuration
// ============================================================================

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub min_confidence: Option<Confidence>,
    pub min_severity: Option<Severity>,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub rules: HashMap<String, RuleConfig>,
    pub min_confidence: Option<Confidence>,
    pub min_severity: Option<Severity>,
    #[serde(default)]
    pub ignore_paths: Vec<String>,
    #[serde(default)]
    pub only_rules: Vec<String>,
    #[serde(default)]
    pub exclude_rules: Vec<String>,
}

impl AppConfig {
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        // Check only_rules first
        if !self.only_rules.is_empty() && !self.only_rules.iter().any(|r| r == rule_id) {
            return false;
        }
        // Check exclude_rules
        if self.exclude_rules.iter().any(|r| r == rule_id) {
            return false;
        }
        // Check per-rule config
        self.rules
            .get(rule_id)
            .map(|c| c.enabled)
            .unwrap_or(true)
    }

    pub fn should_report(&self, finding: &Finding) -> bool {
        if let Some(min_conf) = &self.min_confidence {
            if finding.confidence < *min_conf {
                return false;
            }
        }
        if let Some(min_sev) = &self.min_severity {
            if finding.severity < *min_sev {
                return false;
            }
        }
        true
    }
}

// ============================================================================
// Ignore Comments Parser
// ============================================================================

/// Parsed ignore directive from source comments.
#[derive(Clone, Debug)]
pub struct IgnoreDirective {
    pub line: usize,
    pub rules: Option<Vec<String>>, // None = ignore all
    pub reason: Option<String>,
}

/// Parse auditforge-ignore comments from source code.
/// Supports:
/// - `// auditforge-ignore` (ignore all on next line)
/// - `// auditforge-ignore reentrancy` (ignore specific rule)
/// - `// auditforge-ignore reentrancy, overflow -- reason here`
/// - `// auditforge-disable` (ignore all in block until enable)
pub fn parse_ignore_comments(source: &str) -> Vec<IgnoreDirective> {
    let mut directives = Vec::new();
    let ignore_re = regex::Regex::new(
        r"//\s*auditforge-ignore(?:\s+([a-z0-9_\-,\s]+))?(?:\s*--\s*(.+))?$"
    ).unwrap();

    for (line_num, line) in source.lines().enumerate() {
        if let Some(caps) = ignore_re.captures(line.trim()) {
            let rules = caps.get(1).map(|m| {
                m.as_str()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            });
            let reason = caps.get(2).map(|m| m.as_str().to_string());
            directives.push(IgnoreDirective {
                line: line_num + 2, // Ignore applies to next line (1-indexed)
                rules: if rules.as_ref().map(|v: &Vec<String>| v.is_empty()).unwrap_or(true) {
                    None
                } else {
                    rules
                },
                reason,
            });
        }
    }
    directives
}

/// Check if a finding should be ignored based on directives.
pub fn is_finding_ignored(finding: &Finding, directives: &[IgnoreDirective]) -> bool {
    let finding_line = finding.location.as_ref().and_then(|s| s.line);
    if let Some(line) = finding_line {
        for directive in directives {
            if directive.line == line {
                match &directive.rules {
                    None => return true, // Ignore all
                    Some(rules) => {
                        if rules.iter().any(|r| r == &finding.rule_id) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

// ============================================================================
// Source Utilities
// ============================================================================

/// Helper to compute line/column from byte offset.
pub fn offset_to_line_col(source: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;
    for (i, ch) in source.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Extract source line by line number (1-indexed).
pub fn get_source_line(source: &str, line: usize) -> Option<&str> {
    source.lines().nth(line.saturating_sub(1))
}

// ============================================================================
// Rule Trait & Context
// ============================================================================

/// Context passed to rules for analysis.
pub struct RuleContext {
    pub ast: Arc<AstNode>,
    pub source: Arc<str>,
    pub file_path: PathBuf,
    pub config: AppConfig,
    pub ignore_directives: Vec<IgnoreDirective>,
}

impl RuleContext {
    pub fn new(ast: AstNode, source: String, file_path: PathBuf, config: AppConfig) -> Self {
        let ignore_directives = parse_ignore_comments(&source);
        Self {
            ast: Arc::new(ast),
            source: Arc::from(source.as_str()),
            file_path,
            config,
            ignore_directives,
        }
    }

    /// Get line/column for a byte offset.
    pub fn offset_to_line_col(&self, offset: usize) -> (usize, usize) {
        offset_to_line_col(&self.source, offset)
    }

    /// Create a Span with line/column info.
    pub fn make_span(&self, start: usize, end: usize) -> Span {
        let (line, col) = self.offset_to_line_col(start);
        Span::new(start, end, self.file_path.display().to_string())
            .with_line_col(line, col)
    }
}

/// Trait for security rules.
pub trait Rule: Send + Sync {
    /// Unique rule identifier (e.g., "reentrancy").
    fn id(&self) -> &'static str;

    /// Human-readable rule name.
    fn name(&self) -> &'static str;

    /// Detailed description.
    fn description(&self) -> &'static str;

    /// Default severity for findings from this rule.
    fn severity(&self) -> Severity;

    /// Default confidence level.
    fn confidence(&self) -> Confidence;

    /// SWC ID if applicable (e.g., "SWC-107").
    fn swc_id(&self) -> Option<&'static str> {
        None
    }

    /// CWE ID if applicable (e.g., "CWE-841").
    fn cwe_id(&self) -> Option<&'static str> {
        None
    }

    /// List of rule IDs this rule depends on.
    fn dependencies(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Perform analysis and return findings.
    fn analyze(&self, ctx: &RuleContext) -> Vec<Finding>;
}

// ============================================================================
// Rule Registry
// ============================================================================

#[derive(Default)]
pub struct RuleRegistry {
    rules: RwLock<HashMap<String, Arc<dyn Rule>>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, rule: Arc<dyn Rule>) {
        let mut lock = self.rules.write();
        lock.insert(rule.id().to_string(), rule);
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Rule>> {
        self.rules.read().get(id).cloned()
    }

    pub fn all(&self) -> Vec<Arc<dyn Rule>> {
        self.rules.read().values().cloned().collect()
    }

    pub fn ids(&self) -> Vec<String> {
        self.rules.read().keys().cloned().collect()
    }

    /// Run all enabled rules in parallel and collect findings.
    pub fn analyze_all(&self, ctx: &RuleContext) -> Vec<Finding> {
        let rules: Vec<_> = self
            .all()
            .into_iter()
            .filter(|r| ctx.config.is_rule_enabled(r.id()))
            .collect();

        let mut findings: Vec<Finding> = rules
            .par_iter()
            .flat_map(|rule| rule.analyze(ctx))
            .collect();

        // Filter by ignore directives
        findings.retain(|f| !is_finding_ignored(f, &ctx.ignore_directives));

        // Filter by config
        findings.retain(|f| ctx.config.should_report(f));

        // Sort by severity (highest first), then by location
        findings.sort_by(|a, b| {
            b.severity.cmp(&a.severity).then_with(|| {
                let a_line = a.location.as_ref().and_then(|s| s.line).unwrap_or(0);
                let b_line = b.location.as_ref().and_then(|s| s.line).unwrap_or(0);
                a_line.cmp(&b_line)
            })
        });

        findings
    }

    /// Analyze with progress callback.
    pub fn analyze_with_progress<F>(&self, ctx: &RuleContext, mut on_rule: F) -> Vec<Finding>
    where
        F: FnMut(&str),
    {
        let rules: Vec<_> = self
            .all()
            .into_iter()
            .filter(|r| ctx.config.is_rule_enabled(r.id()))
            .collect();

        let mut all_findings = Vec::new();

        for rule in &rules {
            on_rule(rule.id());
            let findings = rule.analyze(ctx);
            all_findings.extend(findings);
        }

        // Filter by ignore directives
        all_findings.retain(|f| !is_finding_ignored(f, &ctx.ignore_directives));

        // Filter by config
        all_findings.retain(|f| ctx.config.should_report(f));

        // Sort
        all_findings.sort_by(|a, b| {
            b.severity.cmp(&a.severity).then_with(|| {
                let a_line = a.location.as_ref().and_then(|s| s.line).unwrap_or(0);
                let b_line = b.location.as_ref().and_then(|s| s.line).unwrap_or(0);
                a_line.cmp(&b_line)
            })
        });

        all_findings
    }
}

// ============================================================================
// Config Loading
// ============================================================================

pub fn parse_config(raw: &str) -> anyhow::Result<AppConfig> {
    toml::from_str::<AppConfig>(raw).map_err(anyhow::Error::from)
}

pub fn load_default_config() -> AppConfig {
    AppConfig {
        rules: HashMap::new(),
        min_confidence: Some(Confidence::Low),
        min_severity: Some(Severity::Info),
        ignore_paths: Vec::new(),
        only_rules: Vec::new(),
        exclude_rules: Vec::new(),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRule;
    impl Rule for TestRule {
        fn id(&self) -> &'static str { "test-rule" }
        fn name(&self) -> &'static str { "Test Rule" }
        fn description(&self) -> &'static str { "A test rule" }
        fn severity(&self) -> Severity { Severity::High }
        fn confidence(&self) -> Confidence { Confidence::High }
        fn analyze(&self, ctx: &RuleContext) -> Vec<Finding> {
            vec![Finding::new("test-rule", "Test Finding")
                .with_severity(Severity::High)
                .with_confidence(Confidence::High)
                .with_location(ctx.make_span(0, 10))]
        }
    }

    #[test]
    fn registry_runs_rule() {
        let registry = RuleRegistry::new();
        registry.register(Arc::new(TestRule));
        let ctx = RuleContext::new(
            AstNode::new("root", None, vec![]),
            "test source".into(),
            PathBuf::from("test.sol"),
            load_default_config(),
        );
        let findings = registry.analyze_all(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "test-rule");
    }

    #[test]
    fn ignore_directive_works() {
        let source = r#"
// auditforge-ignore test-rule
vulnerable_code();
"#;
        let directives = parse_ignore_comments(source);
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].line, 3);
        assert_eq!(directives[0].rules, Some(vec!["test-rule".to_string()]));
    }

    #[test]
    fn offset_to_line_col_works() {
        let source = "line1\nline2\nline3";
        assert_eq!(offset_to_line_col(source, 0), (1, 1));
        assert_eq!(offset_to_line_col(source, 6), (2, 1));
        assert_eq!(offset_to_line_col(source, 8), (2, 3));
    }

    #[test]
    fn config_filters_rules() {
        let mut config = load_default_config();
        config.only_rules = vec!["allowed-rule".into()];
        
        assert!(config.is_rule_enabled("allowed-rule"));
        assert!(!config.is_rule_enabled("other-rule"));
    }

    #[test]
    fn ast_find_works() {
        let ast = AstNode::new("Contract", None, vec![
            AstNode::new("Function", None, vec![]),
            AstNode::new("Variable", None, vec![]),
        ]);
        let functions = ast.find_all(|n| n.kind == "Function");
        assert_eq!(functions.len(), 1);
    }
}
