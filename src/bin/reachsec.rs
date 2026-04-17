use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use reachsec::application::local_checker::LocalChecker;
use reachsec::application::reachability_analyzer::ReachabilityStatus;
use std::io::IsTerminal;
use std::path::PathBuf;

const DEFAULT_MAX_CALL_CHAINS: usize = 5;

#[derive(Parser)]
#[command(name = "reachsec")]
#[command(about = "RustSec reachability checker for local Rust projects")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check advisories affecting the current project, similar to cargo audit
    Check {
        /// Project path, defaults to the current directory
        #[arg(long, default_value = ".")]
        path: String,

        /// Maximum number of call chains to display per advisory
        #[arg(long, default_value_t = DEFAULT_MAX_CALL_CHAINS)]
        max_call_chains: usize,

        /// Show all call chains without truncation
        #[arg(long)]
        show_all_call_chains: bool,

        /// Output results as JSON
        #[arg(long)]
        json: bool,

        /// Working directory for temporary analysis files (default: system temp dir)
        #[arg(long)]
        work_dir: Option<PathBuf>,

        /// Keep the temporary work directory after analysis (useful for debugging)
        #[arg(long)]
        keep_work_dir: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let cli = Cli::parse();

    let has_vulnerable = match cli.command {
        Commands::Check {
            path,
            max_call_chains,
            show_all_call_chains,
            json,
            work_dir,
            keep_work_dir,
        } => {
            let source_path = PathBuf::from(path);
            if !json {
                println!(
                    "{} {}\n",
                    style_label("Preparing local project"),
                    style_path(source_path.display().to_string())
                );
            }
            let prepared_path =
                LocalChecker::prepare_local_project(&source_path, work_dir.as_deref()).await?;
            if !json {
                println!(
                    "{} {}\n",
                    style_label("Scanning dependencies in"),
                    style_path(source_path.display().to_string())
                );
            }

            let checker = LocalChecker::new(prepared_path.clone())?;
            let results = checker.check().await?;

            let has_vulnerable = results
                .iter()
                .any(|r| r.status == ReachabilityStatus::Reachable);

            if json {
                let json_results: Vec<serde_json::Value> = results
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "advisory_id": r.advisory_id,
                            "package": r.package,
                            "version": r.version,
                            "status": match r.status {
                                ReachabilityStatus::Reachable => "reachable",
                                ReachabilityStatus::NotReachable => "not_reachable",
                                ReachabilityStatus::AnalysisFailed => "analysis_failed",
                                ReachabilityStatus::NoMetadata => "no_metadata",
                            },
                            "title": r.title,
                            "url": r.url,
                            "affected_functions": r.affected_functions,
                            "call_chains": r.call_chains,
                            "errors": r.errors,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&json_results)?);
            } else if results.is_empty() {
                println!("{}", style_success("✓ No advisories found"));
            } else {
                println!("{} {}\n", style_label("Found"), style_count(results.len()));
                for result in results {
                    let status_str = match result.status {
                        ReachabilityStatus::Reachable => "✗ VULNERABLE",
                        ReachabilityStatus::NotReachable => "⚠ POTENTIALLY VULNERABLE",
                        ReachabilityStatus::AnalysisFailed => "⚠ ANALYSIS FAILED",
                        ReachabilityStatus::NoMetadata => "ℹ INFO",
                    };
                    let partial =
                        result.status == ReachabilityStatus::Reachable && !result.errors.is_empty();
                    println!(
                        "{}{}",
                        style_status(status_str),
                        if partial {
                            format!(
                                " {} {}",
                                style_advisory(&result.advisory_id),
                                style_hint("(partial - some functions failed to analyze)")
                            )
                        } else {
                            format!(" {}", style_advisory(&result.advisory_id))
                        }
                    );
                    let affected_summary = match result.status {
                        ReachabilityStatus::Reachable => format!(
                            "{} known function(s); {} call path(s) found",
                            result.affected_functions.len(),
                            result.call_chains.len()
                        ),
                        ReachabilityStatus::NotReachable => format!(
                            "{} known function(s); no call paths found",
                            result.affected_functions.len()
                        ),
                        ReachabilityStatus::AnalysisFailed => format!(
                            "{} known function(s); analysis failed",
                            result.affected_functions.len()
                        ),
                        ReachabilityStatus::NoMetadata => {
                            "No function-level metadata available".to_string()
                        }
                    };
                    println!(
                        "  {} {}",
                        style_field("Affected:"),
                        style_hint(&affected_summary)
                    );

                    if !result.affected_functions.is_empty() {
                        println!("  {}", style_field("Affected functions:"));
                        for func in &result.affected_functions {
                            println!("    - {}", style_function(func));
                        }
                    }

                    if !result.call_chains.is_empty() {
                        println!("  {}", style_field("Call chains:"));
                        let shown_count = if show_all_call_chains {
                            result.call_chains.len()
                        } else {
                            max_call_chains.max(1).min(result.call_chains.len())
                        };
                        for chain in result.call_chains.iter().take(shown_count) {
                            println!("    {}", style_chain(chain));
                        }
                        let hidden_count = result.call_chains.len().saturating_sub(shown_count);
                        if hidden_count > 0 {
                            println!(
                                "    {}",
                                style_hint(&format!(
                                    "... and {hidden_count} more. Re-run with --show-all-call-chains or --max-call-chains {}",
                                    result.call_chains.len()
                                ))
                            );
                        }
                    }

                    println!(
                        "  {} {} {}",
                        style_field("Package:"),
                        style_package(&result.package),
                        style_version(&result.version)
                    );
                    println!("  {} {}", style_field("Title:"), result.title);

                    if !result.errors.is_empty() {
                        println!("  {}", style_field("Errors:"));
                        for err in &result.errors {
                            println!("    {}", style_hint(err));
                        }
                    }
                    println!();
                }
            }

            if !keep_work_dir {
                let _ = tokio::fs::remove_dir_all(&prepared_path).await;
            } else if !json {
                println!(
                    "{} {}",
                    style_hint("Work directory kept at:"),
                    style_path(prepared_path.display().to_string())
                );
            }

            has_vulnerable
        }
    };

    if has_vulnerable {
        std::process::exit(1);
    }

    Ok(())
}

fn colors_enabled() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn style_label(text: &str) -> String {
    if colors_enabled() {
        text.bold().cyan().to_string()
    } else {
        text.to_string()
    }
}

fn style_field(text: &str) -> String {
    if colors_enabled() {
        text.bold().to_string()
    } else {
        text.to_string()
    }
}

fn style_status(text: &str) -> String {
    if !colors_enabled() {
        return text.to_string();
    }

    match text {
        "✗ VULNERABLE" => text.bold().red().to_string(),
        "⚠ POTENTIALLY VULNERABLE" => text.bold().yellow().to_string(),
        _ => text.bold().blue().to_string(),
    }
}

fn style_success(text: &str) -> String {
    if colors_enabled() {
        text.bold().green().to_string()
    } else {
        text.to_string()
    }
}

fn style_path(text: String) -> String {
    if colors_enabled() {
        text.bright_blue().to_string()
    } else {
        text
    }
}

fn style_count(count: usize) -> String {
    let text = format!("{count} advisories:");
    if colors_enabled() {
        text.bold().yellow().to_string()
    } else {
        text
    }
}

fn style_advisory(text: &str) -> String {
    if colors_enabled() {
        text.bold().magenta().to_string()
    } else {
        text.to_string()
    }
}

fn style_package(text: &str) -> String {
    if colors_enabled() {
        text.green().to_string()
    } else {
        text.to_string()
    }
}

fn style_version(text: &str) -> String {
    if colors_enabled() {
        text.yellow().to_string()
    } else {
        text.to_string()
    }
}

fn style_function(text: &str) -> String {
    if colors_enabled() {
        text.bright_magenta().to_string()
    } else {
        text.to_string()
    }
}

fn style_chain(text: &str) -> String {
    if colors_enabled() {
        text.bright_black().to_string()
    } else {
        text.to_string()
    }
}

fn style_hint(text: &str) -> String {
    if colors_enabled() {
        text.bright_black().italic().to_string()
    } else {
        text.to_string()
    }
}
