use anyhow::{Context, Result};
use rustsec::Vulnerability;
use std::path::PathBuf;
use tokio::process::Command;

pub struct ReachabilityAnalyzer {
    project_root: PathBuf,
}

#[derive(Debug, PartialEq)]
pub enum ReachabilityStatus {
    /// Call path to vulnerable function found
    Reachable,
    /// Vulnerable functions known but no call path found
    NotReachable,
    /// Analysis could not be completed (tool missing, timeout, etc.)
    AnalysisFailed,
    /// No function-level metadata in advisory
    NoMetadata,
}

pub struct ReachabilityResult {
    pub status: ReachabilityStatus,
    pub call_chains: Vec<String>,
    pub errors: Vec<String>,
}

impl ReachabilityAnalyzer {
    pub fn new(project_root: PathBuf) -> Result<Self> {
        which::which("call-cg4rs").with_context(|| {
            "call-cg4rs not found in PATH.\n\
             Install it with:\n\n\
             \x20 rustup toolchain install nightly\n\
             \x20 cargo +nightly install --path callgraph4rs --force\n\n\
             See https://github.com/xizheyin/rustsec-reachability for details."
        })?;
        Ok(Self { project_root })
    }

    pub async fn analyze(&self, vuln: &Vulnerability) -> Result<ReachabilityResult> {
        let affected_functions = match vuln.affected_functions() {
            Some(funcs) if !funcs.is_empty() => funcs,
            _ => {
                return Ok(ReachabilityResult {
                    status: ReachabilityStatus::NoMetadata,
                    call_chains: Vec::new(),
                    errors: Vec::new(),
                });
            }
        };

        let function_paths = affected_functions
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>();

        self.analyze_function_paths(&function_paths).await
    }

    pub async fn analyze_function_paths(
        &self,
        function_paths: &[String],
    ) -> Result<ReachabilityResult> {
        if function_paths.is_empty() {
            return Ok(ReachabilityResult {
                status: ReachabilityStatus::NoMetadata,
                call_chains: Vec::new(),
                errors: Vec::new(),
            });
        }

        let output_dir = self.project_root.join(".reachsec/analysis");
        tokio::fs::create_dir_all(&output_dir).await?;
        let mut errors = Vec::new();

        for function_path in function_paths {
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(120),
                Command::new("call-cg4rs")
                    .current_dir(&self.project_root)
                    .args([
                        "--find-callers",
                        function_path,
                        "--json-output",
                        "--output-dir",
                        &output_dir.to_string_lossy(),
                    ])
                    .output(),
            )
            .await;

            match output {
                Ok(Ok(result)) if result.status.success() => {}
                Ok(Ok(result)) => {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    errors.push(format!("Analysis failed for {function_path}: {stderr}"));
                }
                Ok(Err(e)) => {
                    errors.push(format!("Failed to run call-cg4rs for {function_path}: {e}"));
                }
                Err(_) => {
                    errors.push(format!("Timed out analyzing {function_path}"));
                }
            }
        }

        let call_chains = self.parse_callers_output(&output_dir, &mut errors).await?;

        let status = if !call_chains.is_empty() {
            ReachabilityStatus::Reachable
        } else if !errors.is_empty() {
            ReachabilityStatus::AnalysisFailed
        } else {
            ReachabilityStatus::NotReachable
        };

        Ok(ReachabilityResult {
            status,
            call_chains,
            errors,
        })
    }

    async fn parse_callers_output(
        &self,
        output_dir: &PathBuf,
        errors: &mut Vec<String>,
    ) -> Result<Vec<String>> {
        let mut chains = Vec::new();

        let mut entries = tokio::fs::read_dir(output_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && name.starts_with("callers-")
                && name.ends_with(".json")
            {
                let content = tokio::fs::read_to_string(&path).await?;
                match serde_json::from_str::<serde_json::Value>(&content) {
                    Err(e) => {
                        errors.push(format!("Failed to parse {}: {e}", path.display()));
                    }
                    Ok(json) => {
                        if let Some(arr) = json.as_array() {
                            for item in arr {
                                if let Some(caller) = item
                                    .get("caller")
                                    .and_then(|c| c.get("path"))
                                    .and_then(|p| p.as_str())
                                {
                                    let caller = format!("→ {}", caller);
                                    if !chains.contains(&caller) {
                                        chains.push(caller);
                                    }
                                }
                            }
                        } else if let Some(arr) = json.get("callers").and_then(|v| v.as_array()) {
                            for item in arr {
                                if let Some(path_nodes) =
                                    item.get("call_path").and_then(|v| v.as_array())
                                {
                                    let chain = path_nodes
                                        .iter()
                                        .filter_map(|node| node.as_str())
                                        .collect::<Vec<_>>()
                                        .join(" -> ");
                                    if !chain.is_empty() {
                                        let chain = format!("→ {}", chain);
                                        if !chains.contains(&chain) {
                                            chains.push(chain);
                                        }
                                        continue;
                                    }
                                }

                                if let Some(caller) = item.get("path").and_then(|p| p.as_str()) {
                                    let chain = format!("→ {}", caller);
                                    if !chains.contains(&chain) {
                                        chains.push(chain);
                                    }
                                }
                            }
                        } else {
                            errors.push(format!("Unrecognized JSON format in {}", path.display()));
                        }
                    }
                }
            }
        }

        Ok(chains)
    }
}
