use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::{env, fs};

use serde::Deserialize;

mod cli;
mod context;
mod error;
use cli::Command;
use context::*;
use error::XtaskError;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
struct Component {
    path: String,
    kind: String,
    role: String,
    gate: String,
    workspace: String,
    artifact: String,
}

#[cfg(test)]
#[derive(Default)]
struct ComponentBuilder {
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
struct Target {
    name: String,
    triple: String,
    status: String,
    features: String,
    artifact: String,
    evidence: String,
}

#[cfg(test)]
#[derive(Default)]
struct TargetBuilder {
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
struct Artifact {
    name: String,
    platform: String,
    status: String,
    format: String,
    producer: String,
    output: String,
    selection: String,
    immutable_inputs: String,
    hash_evidence: String,
}

#[cfg(test)]
#[allow(dead_code)]
#[derive(Default)]
struct ArtifactBuilder {
    fields: BTreeMap<String, String>,
}

#[cfg(test)]
#[allow(dead_code)]
impl ArtifactBuilder {
    fn finish(self, line: usize) -> Result<Artifact, String> {
        let get = |name: &str| {
            self.fields
                .get(name)
                .cloned()
                .ok_or_else(|| format!("artifact ending at line {line} is missing {name}"))
        };
        Ok(Artifact {
            name: get("name")?,
            platform: get("platform")?,
            status: get("status")?,
            format: get("format")?,
            producer: get("producer")?,
            output: get("output")?,
            selection: get("selection")?,
            immutable_inputs: get("immutable_inputs")?,
            hash_evidence: get("hash_evidence")?,
        })
    }
}

#[cfg(test)]
impl TargetBuilder {
    fn finish(self, line: usize) -> Result<Target, String> {
        let get = |name: &str| {
            self.fields
                .get(name)
                .cloned()
                .ok_or_else(|| format!("target ending at line {line} is missing {name}"))
        };
        Ok(Target {
            name: get("name")?,
            triple: get("triple")?,
            status: get("status")?,
            features: get("features")?,
            artifact: get("artifact")?,
            evidence: get("evidence")?,
        })
    }
}

#[cfg(test)]
impl ComponentBuilder {
    fn finish(self, line: usize) -> Result<Component, String> {
        let get = |name: &str| {
            self.fields
                .get(name)
                .cloned()
                .ok_or_else(|| format!("component ending at line {line} is missing {name}"))
        };
        Ok(Component {
            path: get("path")?,
            kind: get("kind")?,
            role: get("role")?,
            gate: get("gate")?,
            workspace: get("workspace")?,
            artifact: get("artifact")?,
        })
    }
}

fn parse_quoted(value: &str, line: usize) -> Result<String, String> {
    let value = value.trim();
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return Err(format!("line {line}: expected a quoted string"));
    }
    let inner = &value[1..value.len() - 1];
    if inner.contains('"') || inner.contains('\\') {
        return Err(format!(
            "line {line}: escapes are intentionally unsupported in component fields"
        ));
    }
    Ok(inner.to_owned())
}

fn load_components(root: &Path) -> Result<Vec<Component>, String> {
    let path = root.join(COMPONENT_MANIFEST);
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    #[derive(Deserialize)]
    struct Manifest {
        format_version: u32,
        component: Vec<Component>,
    }
    let manifest: Manifest = toml::from_str(&text)
        .map_err(|error| format!("{}: invalid TOML: {error}", path.display()))?;
    if manifest.format_version != 1 {
        return Err(format!("{}: unsupported format_version", path.display()));
    }
    Ok(manifest.component)
}

#[cfg(test)]
fn parse_components(text: &str) -> Result<Vec<Component>, String> {
    let mut components = Vec::new();
    let mut current: Option<ComponentBuilder> = None;

    for (index, raw) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() || line.starts_with("format_version") {
            continue;
        }
        if line == "[[component]]" {
            if let Some(builder) = current.take() {
                components.push(builder.finish(line_number - 1)?);
            }
            current = Some(ComponentBuilder::default());
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {line_number}: expected key = value"));
        };
        let key = key.trim();
        if !matches!(
            key,
            "path" | "kind" | "role" | "gate" | "workspace" | "artifact"
        ) {
            return Err(format!("line {line_number}: unknown component field {key}"));
        }
        let builder = current
            .as_mut()
            .ok_or_else(|| format!("line {line_number}: field outside [[component]]"))?;
        if builder
            .fields
            .insert(key.to_owned(), parse_quoted(value, line_number)?)
            .is_some()
        {
            return Err(format!("line {line_number}: duplicate field {key}"));
        }
    }
    if let Some(builder) = current {
        components.push(builder.finish(text.lines().count())?);
    }
    if components.is_empty() {
        return Err("component manifest is empty".to_owned());
    }
    Ok(components)
}

fn load_targets(root: &Path) -> Result<Vec<Target>, String> {
    let path = root.join(TARGET_MANIFEST);
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    #[derive(Deserialize)]
    struct Manifest {
        format_version: u32,
        target: Vec<Target>,
    }
    let manifest: Manifest = toml::from_str(&text)
        .map_err(|error| format!("{}: invalid TOML: {error}", path.display()))?;
    if manifest.format_version != 1 {
        return Err(format!("{}: unsupported format_version", path.display()));
    }
    Ok(manifest.target)
}

fn load_artifacts(root: &Path) -> Result<Vec<Artifact>, String> {
    let path = root.join(ARTIFACT_MANIFEST);
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    #[derive(Deserialize)]
    struct Manifest {
        format_version: u32,
        artifact: Vec<Artifact>,
    }
    let manifest: Manifest = toml::from_str(&text)
        .map_err(|error| format!("{}: invalid TOML: {error}", path.display()))?;
    if manifest.format_version != 1 {
        return Err(format!("{}: unsupported format_version", path.display()));
    }
    Ok(manifest.artifact)
}

#[cfg(test)]
#[allow(dead_code)]
fn parse_artifacts(text: &str) -> Result<Vec<Artifact>, String> {
    let mut artifacts = Vec::new();
    let mut current: Option<ArtifactBuilder> = None;
    for (index, raw) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() || line.starts_with("format_version") {
            continue;
        }
        if line == "[[artifact]]" {
            if let Some(builder) = current.take() {
                artifacts.push(builder.finish(line_number - 1)?);
            }
            current = Some(ArtifactBuilder::default());
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {line_number}: expected key = value"));
        };
        let key = key.trim();
        if !matches!(
            key,
            "name"
                | "platform"
                | "status"
                | "format"
                | "producer"
                | "output"
                | "selection"
                | "immutable_inputs"
                | "hash_evidence"
        ) {
            return Err(format!("line {line_number}: unknown artifact field {key}"));
        }
        let builder = current
            .as_mut()
            .ok_or_else(|| format!("line {line_number}: field outside [[artifact]]"))?;
        if builder
            .fields
            .insert(key.to_owned(), parse_quoted(value, line_number)?)
            .is_some()
        {
            return Err(format!("line {line_number}: duplicate field {key}"));
        }
    }
    if let Some(builder) = current {
        artifacts.push(builder.finish(text.lines().count())?);
    }
    if artifacts.is_empty() {
        return Err("artifact manifest is empty".to_owned());
    }
    Ok(artifacts)
}

fn validate_artifacts(artifacts: &[Artifact], targets: &[Target]) -> Result<(), String> {
    let target_names = targets
        .iter()
        .map(|target| target.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut names = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    for artifact in artifacts {
        if !names.insert(&artifact.name) {
            return Err(format!("duplicate artifact name: {}", artifact.name));
        }
        if !outputs.insert(&artifact.output) {
            return Err(format!("duplicate artifact output: {}", artifact.output));
        }
        if !target_names.contains(artifact.platform.as_str()) {
            return Err(format!(
                "artifact {} references unknown platform {}",
                artifact.name, artifact.platform
            ));
        }
        if !matches!(
            artifact.status.as_str(),
            "shipped" | "supported after HIL" | "experimental"
        ) {
            return Err(format!(
                "artifact {} has unsupported status {}",
                artifact.name, artifact.status
            ));
        }
        let selection = artifact.selection.to_ascii_lowercase();
        if [
            "mtime",
            "newest",
            "most recent",
            "find |",
            "sort -n",
            "tail -n",
        ]
        .iter()
        .any(|forbidden| selection.contains(forbidden))
        {
            return Err(format!(
                "artifact {} uses a mutable or time-based selection rule",
                artifact.name
            ));
        }
        if !artifact.hash_evidence.contains("SHA-256") {
            return Err(format!(
                "artifact {} does not declare SHA-256 evidence",
                artifact.name
            ));
        }
        if !artifact.immutable_inputs.contains("rust-toolchain.toml") {
            return Err(format!(
                "artifact {} does not name the pinned Rust toolchain",
                artifact.name
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn parse_targets(text: &str) -> Result<Vec<Target>, String> {
    let mut targets = Vec::new();
    let mut current: Option<TargetBuilder> = None;
    for (index, raw) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() || line.starts_with("format_version") {
            continue;
        }
        if line == "[[target]]" {
            if let Some(builder) = current.take() {
                targets.push(builder.finish(line_number - 1)?);
            }
            current = Some(TargetBuilder::default());
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {line_number}: expected key = value"));
        };
        let key = key.trim();
        if !matches!(
            key,
            "name" | "triple" | "status" | "features" | "artifact" | "evidence"
        ) {
            return Err(format!("line {line_number}: unknown target field {key}"));
        }
        let builder = current
            .as_mut()
            .ok_or_else(|| format!("line {line_number}: field outside [[target]]"))?;
        if builder
            .fields
            .insert(key.to_owned(), parse_quoted(value, line_number)?)
            .is_some()
        {
            return Err(format!("line {line_number}: duplicate field {key}"));
        }
    }
    if let Some(builder) = current {
        targets.push(builder.finish(text.lines().count())?);
    }
    if targets.is_empty() {
        return Err("target manifest is empty".to_owned());
    }
    let mut names = BTreeSet::new();
    for target in &targets {
        if !names.insert(&target.name) {
            return Err(format!("duplicate target name: {}", target.name));
        }
    }
    Ok(targets)
}

fn should_skip_directory(name: &OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(".git" | ".codegraph" | "target" | "node_modules")
    )
}

fn discover_manifests(
    root: &Path,
    directory: &Path,
    found: &mut BTreeSet<String>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|e| format!("{}: {e}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", directory.display()))?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let file_type = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", entry.path().display()))?;
        if file_type.is_dir() {
            if !should_skip_directory(&entry.file_name()) {
                discover_manifests(root, &entry.path(), found)?;
            }
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name();
        if name != "Cargo.toml" && name != "lakefile.toml" {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        found.insert(relative);
    }
    Ok(())
}

fn validate_inventory(root: &Path, components: &[Component]) -> Result<(), String> {
    let mut listed = BTreeSet::new();
    for component in components {
        if !listed.insert(component.path.clone()) {
            return Err(format!("duplicate component path: {}", component.path));
        }
        let path = root.join(&component.path);
        if !path.is_file() {
            return Err(format!(
                "listed component does not exist: {}",
                component.path
            ));
        }
        let expected_kind = match path.file_name().and_then(OsStr::to_str) {
            Some("Cargo.toml") => "cargo",
            Some("lakefile.toml") => "lean",
            _ => {
                return Err(format!(
                    "unsupported component manifest: {}",
                    component.path
                ))
            }
        };
        if component.kind != expected_kind {
            return Err(format!(
                "{} is kind {}, expected {expected_kind}",
                component.path, component.kind
            ));
        }
    }

    let mut discovered = BTreeSet::new();
    discover_manifests(root, root, &mut discovered)?;
    let unlisted = discovered.difference(&listed).cloned().collect::<Vec<_>>();
    let stale = listed.difference(&discovered).cloned().collect::<Vec<_>>();
    if !unlisted.is_empty() || !stale.is_empty() {
        let mut message = String::from("component inventory mismatch");
        for path in unlisted {
            message.push_str(&format!("\n  unlisted: {path}"));
        }
        for path in stale {
            message.push_str(&format!("\n  stale: {path}"));
        }
        return Err(message);
    }
    Ok(())
}

fn parse_workspace_array(text: &str, key: &str) -> Result<Vec<String>, String> {
    let workspace = text
        .split_once("[workspace]")
        .map(|(_, rest)| rest)
        .ok_or_else(|| "Cargo.toml is missing [workspace]".to_owned())?;
    let workspace = workspace
        .split("\n[")
        .next()
        .ok_or_else(|| "Cargo.toml has an empty [workspace] section".to_owned())?;
    let assignment = format!("{key} = [");
    let mut collecting = false;
    let mut values = Vec::new();

    for (index, raw) in workspace.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if !collecting {
            if line == assignment {
                collecting = true;
            }
            continue;
        }
        if line == "]" {
            return Ok(values);
        }
        for value in line
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            values.push(parse_quoted(value, index + 1)?);
        }
    }

    Err(format!("Cargo.toml [workspace] is missing {key}"))
}

fn workspace_manifest(path: &str) -> String {
    if path == "." {
        "Cargo.toml".to_owned()
    } else {
        format!("{}/Cargo.toml", path.trim_end_matches('/'))
    }
}

fn load_workspace_layout(root: &Path) -> Result<(BTreeSet<String>, BTreeSet<String>), String> {
    let manifest = root.join("Cargo.toml");
    let text = fs::read_to_string(&manifest)
        .map_err(|error| format!("{}: {error}", manifest.display()))?;
    let members = parse_workspace_array(&text, "members")?
        .into_iter()
        .map(|path| workspace_manifest(&path))
        .collect();
    let excluded = parse_workspace_array(&text, "exclude")?
        .into_iter()
        .map(|path| workspace_manifest(&path))
        .collect();
    Ok((members, excluded))
}

fn collect_rootfs_executables(
    directory: &file_structure::Dir<'_>,
    executables: &mut BTreeSet<String>,
) -> Result<(), String> {
    for file in directory.files {
        if matches!(file.kind, file_structure::Kind::Executable)
            && !executables.insert(file.name.to_owned())
        {
            return Err(format!("duplicate rootfs executable: {}", file.name));
        }
    }
    for child in directory.subdirs {
        collect_rootfs_executables(child, executables)?;
    }
    Ok(())
}

fn expected_workspace_disposition(
    component: &Component,
    members: &BTreeSet<String>,
    excluded: &BTreeSet<String>,
) -> &'static str {
    if component.kind != "cargo" {
        "not-cargo"
    } else if component.path == "Cargo.toml" {
        "root"
    } else if members.contains(&component.path) {
        "member"
    } else if excluded.contains(&component.path) {
        "excluded"
    } else {
        "standalone"
    }
}

fn validate_boundary_contract(
    components: &[Component],
    members: &BTreeSet<String>,
    excluded: &BTreeSet<String>,
    rootfs_executables: &BTreeSet<String>,
) -> Result<(), String> {
    let mut artifacts = BTreeMap::new();
    let mut declared_rootfs = BTreeSet::new();
    let mut declared_members = BTreeSet::new();
    let mut declared_excluded = BTreeSet::new();

    for component in components {
        let expected = expected_workspace_disposition(component, members, excluded);
        if component.workspace != expected {
            return Err(format!(
                "{} declares workspace={}, expected {expected}",
                component.path, component.workspace
            ));
        }
        if component.workspace == "member" {
            declared_members.insert(component.path.clone());
        } else if component.workspace == "excluded" {
            declared_excluded.insert(component.path.clone());
        }

        if component.artifact == "none" {
            continue;
        }
        let (kind, name) = component.artifact.split_once(':').ok_or_else(|| {
            format!(
                "{} has invalid artifact {}; expected KIND:NAME or none",
                component.path, component.artifact
            )
        })?;
        if !matches!(
            kind,
            "host" | "boot" | "rootfs" | "firmware" | "experimental"
        ) || name.is_empty()
        {
            return Err(format!(
                "{} has unsupported artifact {}",
                component.path, component.artifact
            ));
        }
        if let Some(previous) = artifacts.insert(component.artifact.clone(), &component.path) {
            return Err(format!(
                "duplicate artifact {}: {previous} and {}",
                component.artifact, component.path
            ));
        }
        if kind == "rootfs" {
            declared_rootfs.insert(name.to_owned());
        }
    }

    if &declared_members != members || &declared_excluded != excluded {
        let mut message = String::from("workspace boundary mismatch");
        for path in members.difference(&declared_members) {
            message.push_str(&format!("\n  workspace member has no component: {path}"));
        }
        for path in declared_members.difference(members) {
            message.push_str(&format!("\n  component is not a workspace member: {path}"));
        }
        for path in excluded.difference(&declared_excluded) {
            message.push_str(&format!("\n  workspace exclude has no component: {path}"));
        }
        for path in declared_excluded.difference(excluded) {
            message.push_str(&format!("\n  component is not explicitly excluded: {path}"));
        }
        return Err(message);
    }

    let missing = rootfs_executables
        .difference(&declared_rootfs)
        .cloned()
        .collect::<Vec<_>>();
    let stale = declared_rootfs
        .difference(rootfs_executables)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() || !stale.is_empty() {
        let mut message = String::from("rootfs artifact boundary mismatch");
        for name in missing {
            message.push_str(&format!("\n  missing component artifact: rootfs:{name}"));
        }
        for name in stale {
            message.push_str(&format!(
                "\n  artifact not shipped by file_structure: rootfs:{name}"
            ));
        }
        return Err(message);
    }

    Ok(())
}

fn validate_boundary(root: &Path, components: &[Component]) -> Result<(), String> {
    let (members, excluded) = load_workspace_layout(root)?;
    let mut rootfs_executables = BTreeSet::new();
    collect_rootfs_executables(&file_structure::STRUCTURE, &mut rootfs_executables)?;
    validate_boundary_contract(components, &members, &excluded, &rootfs_executables)
}

fn render_components(components: &[Component]) -> String {
    let mut components = components.to_vec();
    components.sort_by(|a, b| a.path.cmp(&b.path));
    let mut output = String::from(
        "<!-- Generated by `cargo xtask docs`; do not edit. -->\n\n\
         # Component inventory\n\n\
         | Manifest | Kind | Workspace | Artifact disposition | Role | Required gate |\n\
         |---|---|---|---|---|---|\n",
    );
    for component in components {
        output.push_str(&format!(
            "| `{}` | {} | {} | `{}` | {} | {} |\n",
            component.path,
            component.kind,
            component.workspace,
            component.artifact,
            component.role,
            component.gate
        ));
    }
    output
}

fn load_build_inputs(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = root.join(BUILD_INPUTS);
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut inputs = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{}:{}: expected KEY=value", path.display(), index + 1))?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
            || value.is_empty()
        {
            return Err(format!(
                "{}:{}: invalid build input",
                path.display(),
                index + 1
            ));
        }
        if inputs.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("{}:{}: duplicate {key}", path.display(), index + 1));
        }
    }
    for required in [
        "LIMINE_REPOSITORY",
        "LIMINE_REF",
        "LIMINE_REVISION",
        "OVMF_TAG",
        "OVMF_SHA256",
    ] {
        if !inputs.contains_key(required) {
            return Err(format!("{} is missing {required}", path.display()));
        }
    }
    Ok(inputs)
}

fn render_build_inputs(inputs: &BTreeMap<String, String>) -> String {
    let mut output = String::from(
        "<!-- Generated by `cargo xtask docs`; do not edit. -->\n\n\
         # Immutable build inputs\n\n\
         | Input | Pinned value |\n\
         |---|---|\n",
    );
    for (key, value) in inputs {
        output.push_str(&format!("| `{key}` | `{value}` |\n"));
    }
    output
}

fn render_targets(targets: &[Target]) -> String {
    let mut output = String::from(
        "<!-- Generated by `cargo xtask docs`; do not edit. -->\n\n\
         # Supported target and feature matrix\n\n\
         | Target | Triple | Status | Features | Artifact | Required evidence |\n\
         |---|---|---|---|---|---|\n",
    );
    for target in targets {
        output.push_str(&format!(
            "| {} | `{}` | {} | `{}` | {} | {} |\n",
            target.name,
            target.triple,
            target.status,
            target.features,
            target.artifact,
            target.evidence
        ));
    }
    output
}

fn render_artifacts(artifacts: &[Artifact]) -> String {
    let mut artifacts = artifacts.to_vec();
    artifacts.sort_by(|a, b| a.name.cmp(&b.name));
    let mut output = String::from(
        "<!-- Generated by `cargo xtask docs`; do not edit. -->\n\n\
         # Shipped-image and artifact provenance\n\n\
         This table defines build recipes and selection rules. Per-build SHA-256 values are retained in the evidence location named by each row; generated outputs are not assigned static hashes. Raspberry Pi boot firmware is an external platform/HIL prerequisite rather than a repository-produced image, so its exact revision and hashes belong in retained HIL evidence.\n\n\
         | Artifact | Platform | Status | Format | Producer | Output / identity | Selection rule | Immutable inputs | Hash evidence |\n\
         |---|---|---|---|---|---|---|---|---|\n",
    );
    for artifact in artifacts {
        output.push_str(&format!(
            "| {} | {} | {} | {} | `{}` | `{}` | {} | {} | {} |\n",
            artifact.name,
            artifact.platform,
            artifact.status,
            artifact.format,
            artifact.producer,
            artifact.output,
            artifact.selection,
            artifact.immutable_inputs,
            artifact.hash_evidence
        ));
    }
    output
}

fn render_abi_entries(output: &mut String, title: &str, entries: &[kernel_abi::AbiEntry]) {
    output.push_str(&format!(
        "## {title}\n\n| ID | Name | Availability |\n|---:|---|---|\n"
    ));
    for entry in entries {
        output.push_str(&format!(
            "| {} | `{}` | {} |\n",
            entry.id, entry.name, entry.availability
        ));
    }
    output.push('\n');
}

fn render_abi() -> String {
    let mut output = format!(
        "<!-- Generated by `cargo xtask docs`; do not edit. -->\n\n\
         # axiomos userspace ABI v{}.{}\n\n\
         This catalog contains only interfaces dispatched by shipped kernels. Reserved syscall/BPF numbers, verifier-known but undispatched helpers, and `verifier-cost` instrumentation are not supported ABI.\n\n",
        kernel_abi::AXIOMOS_ABI_MAJOR,
        kernel_abi::AXIOMOS_ABI_MINOR
    );
    render_abi_entries(&mut output, "Syscalls", kernel_abi::SUPPORTED_SYSCALLS);
    render_abi_entries(
        &mut output,
        "BPF commands",
        kernel_abi::SUPPORTED_BPF_COMMANDS,
    );
    render_abi_entries(
        &mut output,
        "BPF map types",
        kernel_abi::SUPPORTED_BPF_MAP_TYPES,
    );
    render_abi_entries(
        &mut output,
        "BPF helpers",
        kernel_abi::SUPPORTED_BPF_HELPERS,
    );
    render_abi_entries(
        &mut output,
        "BPF attach types",
        kernel_abi::SUPPORTED_BPF_ATTACH_TYPES,
    );
    output.pop();
    output
}

fn check_or_write(path: &Path, expected: &str, check: bool) -> Result<(), String> {
    if check {
        let actual = fs::read_to_string(path)
            .map_err(|e| format!("{}: {e}; run `cargo xtask docs`", path.display()))?;
        if actual != expected {
            return Err(format!(
                "{} is stale; run `cargo xtask docs`",
                path.display()
            ));
        }
    } else {
        fs::write(path, expected).map_err(|e| format!("{}: {e}", path.display()))?;
        println!("updated {}", path.display());
    }
    Ok(())
}

fn check_or_write_docs(root: &Path, components: &[Component], check: bool) -> Result<(), String> {
    let targets = load_targets(root)?;
    let artifacts = load_artifacts(root)?;
    validate_artifacts(&artifacts, &targets)?;
    check_or_write(
        &root.join(GENERATED_COMPONENTS),
        &render_components(components),
        check,
    )?;
    check_or_write(
        &root.join(GENERATED_BUILD_INPUTS),
        &render_build_inputs(&load_build_inputs(root)?),
        check,
    )?;
    check_or_write(
        &root.join(GENERATED_TARGETS),
        &render_targets(&targets),
        check,
    )?;
    check_or_write(
        &root.join(GENERATED_ARTIFACTS),
        &render_artifacts(&artifacts),
        check,
    )?;
    check_or_write(&root.join(GENERATED_ABI), &render_abi(), check)?;
    Ok(())
}

fn run_ci(root: &Path, arguments: &[String]) -> Result<(), String> {
    let mut script_arguments = Vec::new();
    for argument in arguments {
        if argument == "--full" {
            continue;
        }
        script_arguments.push(argument.clone());
    }
    let status = ProcessCommand::new(root.join("scripts/verify-engineering-audit.sh"))
        .args(&script_arguments)
        .current_dir(root)
        .status()
        .map_err(|e| format!("failed to run audit gate: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("audit gate exited with {status}"))
    }
}

fn usage() {
    eprintln!(
        "Usage:\n  cargo xtask inventory --check\n  cargo xtask boundary --check\n  cargo xtask docs [--check]\n  cargo xtask ci [--quick|--full|--extended] [audit options]"
    );
}

fn execute() -> Result<(), String> {
    let root = repo_root();
    let components = load_components(&root)?;
    match cli::parse(env::args().skip(1))? {
        Command::Inventory { .. } => {
            validate_inventory(&root, &components)?;
            println!(
                "component inventory: PASS ({} components)",
                components.len()
            );
            Ok(())
        }
        Command::Boundary { .. } => {
            validate_inventory(&root, &components)?;
            validate_boundary(&root, &components)?;
            println!(
                "workspace/artifact boundary: PASS ({} components)",
                components.len()
            );
            Ok(())
        }
        Command::Docs { check } => {
            validate_inventory(&root, &components)?;
            validate_boundary(&root, &components)?;
            check_or_write_docs(&root, &components, check)
        }
        Command::Ci { arguments } => {
            validate_inventory(&root, &components)?;
            validate_boundary(&root, &components)?;
            check_or_write_docs(&root, &components, true)?;
            run_ci(&root, &arguments)
        }
        Command::Help => {
            usage();
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let error = if error.starts_with("unknown xtask command")
                || error.starts_with("missing xtask command")
                || error.contains("accepts only")
                || error.contains("requires exactly")
            {
                XtaskError::Usage(error)
            } else if error.contains("No such file or directory") {
                XtaskError::MissingDependency(error)
            } else if error.starts_with("failed to run audit gate") {
                XtaskError::Infrastructure(error)
            } else {
                XtaskError::Verification(error)
            };
            error.render();
            usage();
            error.exit_code()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        format_version = 1

        [[component]]
        path = "Cargo.toml"
        kind = "cargo"
        role = "root"
        gate = "host"
        workspace = "root"
        artifact = "host:axiomos"
    "#;

    #[test]
    fn parses_component_manifest() {
        let components = parse_components(VALID).expect("valid component manifest");
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].path, "Cargo.toml");
        assert_eq!(components[0].kind, "cargo");
    }

    #[test]
    fn rejects_missing_fields() {
        let invalid = VALID.replace("gate = \"host\"", "");
        let error = parse_components(&invalid).expect_err("gate is required");
        assert!(error.contains("missing gate"));
    }

    #[test]
    fn generated_inventory_is_sorted() {
        let mut components = parse_components(VALID).expect("valid component manifest");
        components.push(Component {
            path: "0/Cargo.toml".to_owned(),
            kind: "cargo".to_owned(),
            role: "crate".to_owned(),
            gate: "host".to_owned(),
            workspace: "member".to_owned(),
            artifact: "none".to_owned(),
        });
        let rendered = render_components(&components);
        assert!(rendered.find("`0/Cargo.toml`").unwrap() < rendered.find("`Cargo.toml`").unwrap());
    }

    #[test]
    fn parses_target_manifest() {
        let targets = parse_targets(
            r#"
            format_version = 1
            [[target]]
            name = "host"
            triple = "x86_64-unknown-linux-gnu"
            status = "supported"
            features = "default"
            artifact = "binary"
            evidence = "tests"
            "#,
        )
        .expect("valid target manifest");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].status, "supported");
    }

    #[test]
    fn artifact_manifest_rejects_time_based_selection() {
        let artifact = Artifact {
            name: "image".to_owned(),
            platform: "host".to_owned(),
            status: "shipped".to_owned(),
            format: "raw".to_owned(),
            producer: "build".to_owned(),
            output: "image.bin".to_owned(),
            selection: "pick newest output by mtime".to_owned(),
            immutable_inputs: "rust-toolchain.toml".to_owned(),
            hash_evidence: "SHA-256 manifest".to_owned(),
        };
        let target = Target {
            name: "host".to_owned(),
            triple: "host".to_owned(),
            status: "supported".to_owned(),
            features: "default".to_owned(),
            artifact: "binary".to_owned(),
            evidence: "tests".to_owned(),
        };
        let error = validate_artifacts(&[artifact], &[target])
            .expect_err("mtime selection must be rejected");
        assert!(error.contains("time-based selection"));
    }

    #[test]
    fn parses_workspace_member_and_exclude_arrays() {
        let manifest = r#"
            [workspace]
            exclude = [
              "excluded",
            ]
            members = [
              ".",
              "member",
            ]

            [workspace.dependencies]
            example = "1"
        "#;
        assert_eq!(
            parse_workspace_array(manifest, "members").unwrap(),
            [".", "member"]
        );
        assert_eq!(
            parse_workspace_array(manifest, "exclude").unwrap(),
            ["excluded"]
        );
    }

    #[test]
    fn boundary_rejects_rootfs_artifact_drift() {
        let components = parse_components(VALID).expect("valid component manifest");
        let members = BTreeSet::new();
        let excluded = BTreeSet::new();
        let rootfs = BTreeSet::from(["init".to_owned()]);
        let error = validate_boundary_contract(&components, &members, &excluded, &rootfs)
            .expect_err("missing rootfs declaration must fail");
        assert!(error.contains("missing component artifact: rootfs:init"));
    }

    #[test]
    fn boundary_rejects_duplicate_artifacts() {
        let mut components = parse_components(VALID).expect("valid component manifest");
        let mut duplicate = components[0].clone();
        duplicate.path = "other/Cargo.toml".to_owned();
        duplicate.workspace = "standalone".to_owned();
        components.push(duplicate);
        let error = validate_boundary_contract(
            &components,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .expect_err("duplicate artifact must fail");
        assert!(error.contains("duplicate artifact host:axiomos"));
    }

    #[test]
    fn boundary_rejects_stale_workspace_member() {
        let components = parse_components(VALID).expect("valid component manifest");
        let members = BTreeSet::from(["missing/Cargo.toml".to_owned()]);
        let error =
            validate_boundary_contract(&components, &members, &BTreeSet::new(), &BTreeSet::new())
                .expect_err("stale workspace member must fail");
        assert!(error.contains("workspace member has no component: missing/Cargo.toml"));
    }
}
