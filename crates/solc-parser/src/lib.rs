//! AuditForge Solidity Parser — Wrapper around solc JSON AST.
//!
//! This crate provides parsing of Solidity files using the solc compiler's
//! JSON AST output, converting it to AuditForge's unified AST model.

use anyhow::{anyhow, Context, Result};
use auditforge_core::{AstNode, Span};
use serde_json::Value;
use std::path::Path;
use std::process::Command;
use tracing::{debug, info, warn};

/// Solidity parser using solc compiler.
pub struct SolcParser {
    solc_path: String,
}

impl Default for SolcParser {
    fn default() -> Self {
        Self {
            solc_path: "solc".to_string(),
        }
    }
}

impl SolcParser {
    /// Create a new parser, checking for solc availability.
    pub fn new() -> Result<Self> {
        let parser = Self::default();

        // Check if solc is available
        match Command::new(&parser.solc_path).arg("--version").output() {
            Ok(output) => {
                if output.status.success() {
                    let version = String::from_utf8_lossy(&output.stdout);
                    debug!("Using solc: {}", version.lines().next().unwrap_or("unknown"));
                    Ok(parser)
                } else {
                    Err(anyhow!(
                        "solc command failed. Ensure solc is installed and in PATH.\n\
                         Install with: npm install -g solc\n\
                         Or download from: https://github.com/ethereum/solidity/releases"
                    ))
                }
            }
            Err(e) => Err(anyhow!(
                "solc not found: {}. Ensure solc is installed and in PATH.\n\
                 Install with: npm install -g solc\n\
                 Or download from: https://github.com/ethereum/solidity/releases",
                e
            )),
        }
    }

    /// Create a parser with a custom solc path.
    pub fn with_solc_path(solc_path: impl Into<String>) -> Self {
        Self {
            solc_path: solc_path.into(),
        }
    }

    /// Parse a Solidity file and return the AST.
    pub fn parse_file<P: AsRef<Path>>(&self, path: P) -> Result<AstNode> {
        let path = path.as_ref();
        let path_str = path.display().to_string();

        info!("Parsing Solidity file: {}", path_str);

        // Run solc with AST output
        let output = Command::new(&self.solc_path)
            .arg("--ast-compact-json")
            .arg(path)
            .output()
            .with_context(|| format!("Failed to run solc on {}", path_str))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Try to extract meaningful error
            if stderr.contains("Error:") {
                return Err(anyhow!("Solidity compilation error:\n{}", stderr));
            }
            warn!("solc returned non-zero exit code, attempting to parse anyway");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Find the JSON AST in the output
        // solc outputs: =======<file>=======\nJSON AST:\n<json>
        let json_start = stdout
            .find('{')
            .ok_or_else(|| anyhow!("No JSON AST found in solc output"))?;

        let json_str = &stdout[json_start..];

        // Find the end of the JSON (next file marker or end)
        let json_end = json_str
            .find("\n======")
            .unwrap_or(json_str.len());

        let json_str = &json_str[..json_end];

        let ast_json: Value = serde_json::from_str(json_str)
            .with_context(|| "Failed to parse solc JSON output")?;

        debug!("Successfully parsed AST for {}", path_str);

        Ok(json_to_ast(&ast_json, &path_str))
    }

    /// Parse Solidity source code directly (without file).
    pub fn parse_source(&self, source: &str, filename: &str) -> Result<AstNode> {
        use std::io::Write;

        // Write to temp file
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(filename);

        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(source.as_bytes())?;

        let result = self.parse_file(&temp_path);

        // Clean up
        let _ = std::fs::remove_file(&temp_path);

        result
    }
}

/// Convert solc JSON AST to AuditForge AstNode.
fn json_to_ast(value: &Value, file_path: &str) -> AstNode {
    let kind = value
        .get("nodeType")
        .and_then(Value::as_str)
        .unwrap_or("Unknown")
        .to_string();

    let name = value
        .get("name")
        .and_then(Value::as_str)
        .map(String::from);

    let span = value
        .get("src")
        .and_then(Value::as_str)
        .and_then(|s| parse_src_string(s, file_path));

    // Collect relevant attributes
    let mut node = AstNode::new(kind, span, Vec::new());

    if let Some(n) = name {
        node = node.with_name(n);
    }

    // Add important attributes
    if let Some(visibility) = value.get("visibility").and_then(Value::as_str) {
        node = node.with_attr("visibility", visibility);
    }
    if let Some(state_mut) = value.get("stateMutability").and_then(Value::as_str) {
        node = node.with_attr("stateMutability", state_mut);
    }
    if let Some(kind) = value.get("kind").and_then(Value::as_str) {
        node = node.with_attr("kind", kind);
    }
    if let Some(op) = value.get("operator").and_then(Value::as_str) {
        node = node.with_attr("operator", op);
    }
    if let Some(is_const) = value.get("constant").and_then(Value::as_bool) {
        node = node.with_attr("constant", is_const.to_string());
    }

    // Process children from various possible fields
    let child_fields = [
        "nodes",
        "body",
        "statements",
        "expression",
        "leftExpression",
        "rightExpression",
        "arguments",
        "components",
        "initialValue",
        "condition",
        "trueBody",
        "falseBody",
        "subExpression",
        "baseExpression",
        "indexExpression",
    ];

    for field in child_fields {
        if let Some(child_val) = value.get(field) {
            match child_val {
                Value::Array(arr) => {
                    for item in arr {
                        if item.is_object() {
                            node.children.push(json_to_ast(item, file_path));
                        }
                    }
                }
                Value::Object(_) => {
                    node.children.push(json_to_ast(child_val, file_path));
                }
                _ => {}
            }
        }
    }

    node
}

/// Parse solc src string format: "start:length:fileIndex"
fn parse_src_string(src: &str, file_path: &str) -> Option<Span> {
    let mut parts = src.split(':');
    let start = parts.next()?.parse::<usize>().ok()?;
    let length = parts.next()?.parse::<usize>().ok()?;

    Some(Span::new(start, start + length, file_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_json_to_ast() {
        let json = json!({
            "nodeType": "ContractDefinition",
            "name": "TestContract",
            "src": "0:100:0",
            "nodes": [
                {
                    "nodeType": "FunctionDefinition",
                    "name": "test",
                    "src": "10:50:0",
                    "visibility": "public"
                }
            ]
        });

        let ast = json_to_ast(&json, "test.sol");

        assert_eq!(ast.kind, "ContractDefinition");
        assert_eq!(ast.name, Some("TestContract".to_string()));
        assert_eq!(ast.children.len(), 1);
        assert_eq!(ast.children[0].kind, "FunctionDefinition");
        assert_eq!(ast.children[0].attr("visibility"), Some("public"));
    }

    #[test]
    fn parses_src_string() {
        let span = parse_src_string("10:20:0", "test.sol").unwrap();
        assert_eq!(span.start, 10);
        assert_eq!(span.end, 30);
        assert_eq!(span.file, "test.sol");
    }

    #[test]
    fn handles_missing_fields() {
        let json = json!({
            "nodeType": "EmptyNode"
        });

        let ast = json_to_ast(&json, "test.sol");
        assert_eq!(ast.kind, "EmptyNode");
        assert!(ast.name.is_none());
        assert!(ast.span.is_none());
        assert!(ast.children.is_empty());
    }
}
