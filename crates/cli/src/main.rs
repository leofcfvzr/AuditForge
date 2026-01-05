//! AuditForge CLI — Static analyzer for Web3 smart contracts.

use anyhow::{Context, Result};
use auditforge_core::{
    load_default_config, parse_config, AppConfig, Confidence, Finding, RuleContext,
    RuleRegistry, Severity,
};
use auditforge_rules::{list_rules, register_all};
use auditforge_solc_parser::SolcParser;
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing_subscriber::EnvFilter;
use walkdir::WalkDir;

// ============================================================================
// CLI Arguments
// ============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "auditforge",
    version,
    about = "Static analyzer for Web3 smart contracts",
    long_about = "AuditForge is a static analysis tool for detecting security vulnerabilities \
                  in Solidity and other smart contract languages. It supports multiple output \
                  formats and can be integrated into CI/CD pipelines."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan files or directories for vulnerabilities
    Scan {
        /// Path to file or directory to scan
        #[arg(short, long)]
        path: PathBuf,

        /// Configuration file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Minimum confidence level to report
        #[arg(long, value_enum, default_value = "low")]
        min_confidence: ConfidenceArg,

        /// Minimum severity level to report
        #[arg(long, value_enum, default_value = "info")]
        min_severity: SeverityArg,

        /// Only run specific rules (comma-separated)
        #[arg(long, value_delimiter = ',')]
        only: Option<Vec<String>>,

        /// Exclude specific rules (comma-separated)
        #[arg(long, value_delimiter = ',')]
        exclude: Option<Vec<String>>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,

        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Recursively scan directories
        #[arg(short, long)]
        recursive: bool,

        /// File extensions to scan (default: sol)
        #[arg(long, value_delimiter = ',', default_value = "sol")]
        extensions: Vec<String>,

        /// Fail with exit code 1 if findings are detected
        #[arg(long)]
        fail_on_findings: bool,
    },

    /// List available rules
    Rules {
        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },

    /// Initialize a new configuration file
    Init {
        /// Output path for configuration file
        #[arg(short, long, default_value = "auditforge.toml")]
        output: PathBuf,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ConfidenceArg {
    High,
    Medium,
    Low,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<ConfidenceArg> for Confidence {
    fn from(value: ConfidenceArg) -> Self {
        match value {
            ConfidenceArg::High => Confidence::High,
            ConfidenceArg::Medium => Confidence::Medium,
            ConfidenceArg::Low => Confidence::Low,
        }
    }
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Critical => Severity::Critical,
            SeverityArg::High => Severity::High,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Info => Severity::Info,
        }
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.no_color {
        colored::control::set_override(false);
    }

    init_tracing(cli.verbose);

    match cli.command {
        Commands::Scan {
            path,
            config,
            min_confidence,
            min_severity,
            only,
            exclude,
            format,
            output,
            recursive,
            extensions,
            fail_on_findings,
        } => {
            let result = run_scan(
                &path,
                config.as_deref(),
                min_confidence.into(),
                min_severity.into(),
                only.unwrap_or_default(),
                exclude.unwrap_or_default(),
                format,
                output.as_deref(),
                recursive,
                &extensions,
            )?;

            if fail_on_findings && !result.is_empty() {
                std::process::exit(1);
            }
        }
        Commands::Rules { format } => {
            print_rules(format)?;
        }
        Commands::Init { output } => {
            init_config(&output)?;
        }
    }

    Ok(())
}

// ============================================================================
// Scan Command
// ============================================================================

fn run_scan(
    path: &Path,
    config_path: Option<&Path>,
    min_confidence: Confidence,
    min_severity: Severity,
    only_rules: Vec<String>,
    exclude_rules: Vec<String>,
    format: OutputFormat,
    output_path: Option<&Path>,
    recursive: bool,
    extensions: &[String],
) -> Result<Vec<Finding>> {
    let start = Instant::now();

    // Load configuration
    let mut config = if let Some(cfg_path) = config_path {
        let content = fs::read_to_string(cfg_path)
            .with_context(|| format!("Failed to read config: {}", cfg_path.display()))?;
        parse_config(&content)?
    } else if let Ok(content) = fs::read_to_string("auditforge.toml") {
        parse_config(&content).unwrap_or_else(|_| load_default_config())
    } else {
        load_default_config()
    };

    // Apply CLI overrides
    config.min_confidence = Some(min_confidence);
    config.min_severity = Some(min_severity);
    if !only_rules.is_empty() {
        config.only_rules = only_rules;
    }
    if !exclude_rules.is_empty() {
        config.exclude_rules = exclude_rules;
    }

    // Collect files to scan
    let files = collect_files(path, recursive, extensions)?;

    if files.is_empty() {
        eprintln!(
            "{}",
            "No files found to scan. Check path and extensions.".yellow()
        );
        return Ok(Vec::new());
    }

    // Setup parser and registry
    let parser = SolcParser::new().context("Failed to initialize Solidity parser")?;
    let registry = RuleRegistry::new();
    register_all(&registry);

    // Progress bar
    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    let mut all_findings = Vec::new();
    let mut errors = Vec::new();

    for file in &files {
        pb.set_message(file.file_name().unwrap_or_default().to_string_lossy().to_string());

        match scan_file(&parser, &registry, file, &config) {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => {
                errors.push((file.clone(), e));
            }
        }

        pb.inc(1);
    }

    pb.finish_and_clear();

    // Report errors
    for (file, error) in &errors {
        eprintln!(
            "{} {}: {}",
            "Error scanning".red(),
            file.display(),
            error
        );
    }

    let elapsed = start.elapsed();

    // Output results
    let output_str = format_output(&all_findings, format, &files, elapsed)?;

    if let Some(out_path) = output_path {
        fs::write(out_path, &output_str)?;
        eprintln!("Results written to {}", out_path.display());
    } else {
        println!("{}", output_str);
    }

    // Summary
    if matches!(format, OutputFormat::Text) {
        print_summary(&all_findings, files.len(), errors.len(), elapsed);
    }

    Ok(all_findings)
}

fn scan_file(
    parser: &SolcParser,
    registry: &RuleRegistry,
    path: &Path,
    config: &AppConfig,
) -> Result<Vec<Finding>> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let ast = parser
        .parse_file(path)
        .with_context(|| format!("Failed to parse {}", path.display()))?;

    let ctx = RuleContext::new(ast, source, path.to_path_buf(), config.clone());

    Ok(registry.analyze_all(&ctx))
}

fn collect_files(path: &Path, recursive: bool, extensions: &[String]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        let walker = if recursive {
            WalkDir::new(path)
        } else {
            WalkDir::new(path).max_depth(1)
        };

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let entry_path = entry.path();
            if entry_path.is_file() {
                if let Some(ext) = entry_path.extension() {
                    if extensions.iter().any(|e| e == ext.to_string_lossy().as_ref()) {
                        files.push(entry_path.to_path_buf());
                    }
                }
            }
        }
    } else {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    Ok(files)
}

// ============================================================================
// Output Formatting
// ============================================================================

fn format_output(
    findings: &[Finding],
    format: OutputFormat,
    files: &[PathBuf],
    elapsed: std::time::Duration,
) -> Result<String> {
    match format {
        OutputFormat::Text => format_text(findings),
        OutputFormat::Json => format_json(findings),
        OutputFormat::Sarif => format_sarif(findings, files, elapsed),
    }
}

fn format_text(findings: &[Finding]) -> Result<String> {
    let mut output = String::new();

    for finding in findings {
        let severity_colored = match finding.severity {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".red(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::Low => "LOW".blue(),
            Severity::Info => "INFO".white(),
        };

        let confidence_str = match finding.confidence {
            Confidence::High => "high confidence",
            Confidence::Medium => "medium confidence",
            Confidence::Low => "low confidence",
        };

        output.push_str(&format!(
            "\n{} {} [{}] ({})\n",
            "●".bold(),
            severity_colored,
            finding.rule_id.cyan(),
            confidence_str.dimmed()
        ));

        output.push_str(&format!("  {}\n", finding.title.bold()));

        if let Some(loc) = &finding.location {
            output.push_str(&format!("  {} {}\n", "Location:".dimmed(), loc));
        }

        if !finding.description.is_empty() {
            output.push_str(&format!("  {}\n", finding.description));
        }

        if let Some(suggestion) = &finding.suggestion {
            output.push_str(&format!("  {} {}\n", "Fix:".green(), suggestion));
        }

        if let Some(swc) = &finding.swc_id {
            output.push_str(&format!(
                "  {} https://swcregistry.io/{}\n",
                "Reference:".dimmed(),
                swc
            ));
        }

        if let Some(trace) = &finding.trace {
            output.push_str(&format!("  {}\n", "Trace:".dimmed()));
            for (i, step) in trace.iter().enumerate() {
                output.push_str(&format!("    {}. {}\n", i + 1, step));
            }
        }
    }

    Ok(output)
}

fn format_json(findings: &[Finding]) -> Result<String> {
    Ok(serde_json::to_string_pretty(findings)?)
}

fn format_sarif(
    findings: &[Finding],
    _files: &[PathBuf],
    _elapsed: std::time::Duration,
) -> Result<String> {
    let rules: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| &f.rule_id)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .map(|id| {
            serde_json::json!({
                "id": id,
                "shortDescription": { "text": id },
                "helpUri": format!("https://swcregistry.io/{}", id)
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            };

            let mut result = serde_json::json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": { "text": f.description.clone() }
            });

            if let Some(loc) = &f.location {
                result["locations"] = serde_json::json!([{
                    "physicalLocation": {
                        "artifactLocation": { "uri": loc.file.clone() },
                        "region": {
                            "startLine": loc.line.unwrap_or(1),
                            "startColumn": loc.column.unwrap_or(1)
                        }
                    }
                }]);
            }

            result
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AuditForge",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/example/auditforge",
                    "rules": rules
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "endTimeUtc": chrono::Utc::now().to_rfc3339()
            }]
        }]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn print_summary(
    findings: &[Finding],
    file_count: usize,
    error_count: usize,
    elapsed: std::time::Duration,
) {
    println!("\n{}", "═".repeat(60).dimmed());

    let mut by_severity: HashMap<&str, usize> = HashMap::new();
    for f in findings {
        let key = match f.severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        };
        *by_severity.entry(key).or_default() += 1;
    }

    if findings.is_empty() {
        println!("{}", "✓ No issues found!".green().bold());
    } else {
        println!(
            "{} {} issue(s) found:",
            "⚠".yellow(),
            findings.len().to_string().bold()
        );

        if let Some(&n) = by_severity.get("critical") {
            println!("  {} critical", n.to_string().red().bold());
        }
        if let Some(&n) = by_severity.get("high") {
            println!("  {} high", n.to_string().red());
        }
        if let Some(&n) = by_severity.get("medium") {
            println!("  {} medium", n.to_string().yellow());
        }
        if let Some(&n) = by_severity.get("low") {
            println!("  {} low", n.to_string().blue());
        }
        if let Some(&n) = by_severity.get("info") {
            println!("  {} info", n.to_string().white());
        }
    }

    println!(
        "\nScanned {} file(s) in {:.2}s",
        file_count,
        elapsed.as_secs_f64()
    );

    if error_count > 0 {
        println!("{} {} file(s) had errors", "⚠".yellow(), error_count);
    }

    println!("{}", "═".repeat(60).dimmed());
}

// ============================================================================
// Rules Command
// ============================================================================

fn print_rules(format: OutputFormat) -> Result<()> {
    let rules = list_rules();

    match format {
        OutputFormat::Text => {
            println!("{}", "Available Rules".bold());
            println!("{}", "─".repeat(60));
            for (id, name, swc) in &rules {
                println!(
                    "  {} {} ({})",
                    "●".cyan(),
                    id.bold(),
                    swc.dimmed()
                );
                println!("    {}", name);
            }
            println!("\nUse --only <rule> to run specific rules");
            println!("Use --exclude <rule> to skip specific rules");
        }
        OutputFormat::Json | OutputFormat::Sarif => {
            let json: Vec<_> = rules
                .iter()
                .map(|(id, name, swc)| {
                    serde_json::json!({
                        "id": id,
                        "name": name,
                        "swc": swc
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }

    Ok(())
}

// ============================================================================
// Init Command
// ============================================================================

fn init_config(output: &Path) -> Result<()> {
    let config = r#"# AuditForge Configuration
# https://github.com/example/auditforge

# Minimum confidence level (low, medium, high)
min_confidence = "low"

# Minimum severity level (info, low, medium, high, critical)
min_severity = "info"

# Paths to ignore (glob patterns)
ignore_paths = [
    "**/node_modules/**",
    "**/test/**",
    "**/mock/**",
]

# Rules to run exclusively (empty = all rules)
only_rules = []

# Rules to exclude
exclude_rules = []

# Per-rule configuration
[rules.reentrancy]
enabled = true

[rules.delegatecall]
enabled = true

[rules.access-control]
enabled = true

[rules.unchecked-return]
enabled = true

[rules.tx-origin]
enabled = true

[rules.overflow]
enabled = true

[rules.uninitialized-storage]
enabled = true
"#;

    if output.exists() {
        anyhow::bail!("Configuration file already exists: {}", output.display());
    }

    fs::write(output, config)?;
    println!(
        "{} Created configuration file: {}",
        "✓".green(),
        output.display()
    );

    Ok(())
}

// ============================================================================
// Utilities
// ============================================================================

fn init_tracing(verbose: bool) {
    let filter = if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::from_default_env()
    };

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
