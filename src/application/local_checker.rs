use crate::application::reachability_analyzer::{
    ReachabilityAnalyzer, ReachabilityResult, ReachabilityStatus,
};
use anyhow::{Context, Result};
use rustsec::{
    Database, Lockfile, Vulnerability, Warning, advisory::Informational, report::Report,
    report::Settings,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::process::Command;

#[derive(Debug)]
pub struct CheckResult {
    pub package: String,
    pub version: String,
    pub advisory_id: String,
    pub status: ReachabilityStatus,
    pub title: String,
    pub description: String,
    pub affected_functions: Vec<String>,
    pub url: String,
    pub call_chains: Vec<String>,
    pub errors: Vec<String>,
}

pub struct LocalChecker {
    db: Database,
    project_root: PathBuf,
    analyzer: ReachabilityAnalyzer,
}

impl LocalChecker {
    pub fn new(project_root: PathBuf) -> Result<Self> {
        let project_root = project_root.canonicalize().with_context(|| {
            format!(
                "Failed to access project directory {}",
                project_root.display()
            )
        })?;

        Ok(Self {
            db: Database::fetch()?,
            analyzer: ReachabilityAnalyzer::new(project_root.clone())?,
            project_root,
        })
    }

    pub async fn check(&self) -> Result<Vec<CheckResult>> {
        let lock_path = self.project_root.join("Cargo.lock");
        let lockfile = Lockfile::load(&lock_path)?;

        let settings = Settings {
            informational_warnings: vec![
                Informational::Notice,
                Informational::Unmaintained,
                Informational::Unsound,
            ],
            ..Default::default()
        };
        let report = Report::generate(&self.db, &lockfile, &settings);

        let mut results = Vec::new();

        for vuln in &report.vulnerabilities.list {
            let result = self.check_reachability(vuln).await?;
            let affected_functions = vuln
                .affected_functions()
                .map(|funcs| funcs.iter().map(|f| f.to_string()).collect())
                .unwrap_or_default();

            results.push(CheckResult {
                package: vuln.package.name.to_string(),
                version: vuln.package.version.to_string(),
                advisory_id: vuln.advisory.id.to_string(),
                status: result.status,
                title: vuln.advisory.title.clone(),
                description: vuln.advisory.description.clone(),
                affected_functions,
                url: format!("https://rustsec.org/advisories/{}", vuln.advisory.id),
                call_chains: result.call_chains,
                errors: result.errors,
            });
        }

        for warnings in report.warnings.values() {
            for warning in warnings {
                if let Some(result) = self.check_warning_reachability(warning).await? {
                    results.push(result);
                }
            }
        }

        Ok(results)
    }

    pub async fn prepare_local_project(
        project_root: &Path,
        work_dir: Option<&Path>,
    ) -> Result<PathBuf> {
        let source_root = project_root.canonicalize().with_context(|| {
            format!(
                "Failed to access project directory {}",
                project_root.display()
            )
        })?;
        let cargo_toml = source_root.join("Cargo.toml");
        if !cargo_toml.exists() {
            return Err(anyhow::anyhow!(
                "Project does not contain Cargo.toml: {}",
                source_root.display()
            ));
        }

        let workspace_root = match work_dir {
            Some(dir) => dir.to_path_buf(),
            None => std::env::temp_dir().join("reachsec"),
        };
        fs::create_dir_all(&workspace_root)
            .await
            .context("Failed to create check workspace root")?;
        let workspace_root = workspace_root.canonicalize().with_context(|| {
            format!(
                "Failed to access check workspace root {}",
                workspace_root.display()
            )
        })?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System clock error")?
            .as_millis();
        let project_name = source_root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("project");
        let workspace_dir = workspace_root.join(format!("{project_name}-{timestamp}"));
        fs::create_dir_all(&workspace_dir)
            .await
            .context("Failed to create temporary check workspace")?;

        let mut ignored_roots = vec![source_root.join(".git"), source_root.join("target")];
        let reachsec_dir = source_root.join(".reachsec");
        if reachsec_dir.exists() {
            ignored_roots.push(reachsec_dir);
        }
        if workspace_root.starts_with(&source_root) {
            ignored_roots.push(workspace_root.clone());
        }

        copy_dir_recursive(&source_root, &workspace_dir, &ignored_roots)
            .await
            .with_context(|| {
                format!(
                    "Failed to copy project {} to {}",
                    source_root.display(),
                    workspace_dir.display()
                )
            })?;

        let lockfile_path = workspace_dir.join("Cargo.lock");
        if !lockfile_path.exists() {
            Self::generate_lockfile(&workspace_dir).await.with_context(|| {
                format!(
                    "Failed to generate Cargo.lock for {} using Cargo's normal dependency resolution.",
                    source_root.display()
                )
            })?;
        }

        workspace_dir.canonicalize().with_context(|| {
            format!(
                "Failed to access prepared project {}",
                workspace_dir.display()
            )
        })
    }

    async fn check_reachability(&self, vuln: &Vulnerability) -> Result<ReachabilityResult> {
        self.analyzer.analyze(vuln).await
    }

    async fn check_warning_reachability(&self, warning: &Warning) -> Result<Option<CheckResult>> {
        let Some(advisory) = warning.advisory.as_ref() else {
            return Ok(None);
        };

        let affected_functions: Vec<String> = warning
            .affected
            .as_ref()
            .map(|affected| affected.functions.keys().map(|f| f.to_string()).collect())
            .unwrap_or_default();

        let result = self
            .analyzer
            .analyze_function_paths(&affected_functions)
            .await?;

        Ok(Some(CheckResult {
            package: warning.package.name.to_string(),
            version: warning.package.version.to_string(),
            advisory_id: advisory.id.to_string(),
            status: result.status,
            title: advisory.title.clone(),
            description: advisory.description.clone(),
            affected_functions,
            url: advisory
                .url
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("https://rustsec.org/advisories/{}", advisory.id)),
            call_chains: result.call_chains,
            errors: result.errors,
        }))
    }

    async fn generate_lockfile(project_root: &Path) -> Result<()> {
        let output = Command::new("cargo")
            .arg("generate-lockfile")
            .current_dir(project_root)
            .output()
            .await
            .context("Failed to run cargo generate-lockfile")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "cargo generate-lockfile failed in {}: {}",
                project_root.display(),
                stderr
            ));
        }

        Ok(())
    }
}

async fn copy_dir_recursive(from: &Path, to: &Path, ignored_roots: &[PathBuf]) -> Result<()> {
    let mut stack = vec![(from.to_path_buf(), to.to_path_buf())];

    while let Some((src_dir, dst_dir)) = stack.pop() {
        fs::create_dir_all(&dst_dir).await?;
        let mut entries = fs::read_dir(&src_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let src_path = entry.path();
            if should_skip_path(&src_path, ignored_roots) {
                continue;
            }
            let dst_path = dst_dir.join(entry.file_name());
            let file_type = entry.file_type().await?;

            if file_type.is_dir() {
                stack.push((src_path, dst_path));
                continue;
            }

            if file_type.is_file() {
                fs::copy(&src_path, &dst_path).await.with_context(|| {
                    format!(
                        "Failed to copy file {} to {}",
                        src_path.display(),
                        dst_path.display()
                    )
                })?;
            }
        }
    }

    Ok(())
}

fn should_skip_path(path: &Path, ignored_roots: &[PathBuf]) -> bool {
    ignored_roots
        .iter()
        .any(|ignored| path.starts_with(ignored))
}
