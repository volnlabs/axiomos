#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::context::{ARTIFACT_MANIFEST, COMPONENT_MANIFEST, TARGET_MANIFEST};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub(crate) struct Component {
    pub(crate) path: String,
    pub(crate) kind: String,
    pub(crate) role: String,
    pub(crate) gate: String,
    pub(crate) workspace: String,
    pub(crate) artifact: String,
}

#[cfg(test)]
#[derive(Default)]
struct ComponentBuilder {
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub(crate) struct Target {
    pub(crate) name: String,
    pub(crate) triple: String,
    pub(crate) status: String,
    pub(crate) features: String,
    pub(crate) artifact: String,
    pub(crate) evidence: String,
}

#[cfg(test)]
#[derive(Default)]
struct TargetBuilder {
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub(crate) struct Artifact {
    pub(crate) name: String,
    pub(crate) platform: String,
    pub(crate) status: String,
    pub(crate) format: String,
    pub(crate) producer: String,
    pub(crate) output: String,
    pub(crate) selection: String,
    pub(crate) immutable_inputs: String,
    pub(crate) hash_evidence: String,
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

pub(crate) fn parse_quoted(value: &str, line: usize) -> Result<String, String> {
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

pub(crate) fn load_components(root: &Path) -> Result<Vec<Component>, String> {
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
pub(crate) fn parse_components(text: &str) -> Result<Vec<Component>, String> {
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

pub(crate) fn load_targets(root: &Path) -> Result<Vec<Target>, String> {
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

pub(crate) fn load_artifacts(root: &Path) -> Result<Vec<Artifact>, String> {
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
pub(crate) fn parse_artifacts(text: &str) -> Result<Vec<Artifact>, String> {
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

pub(crate) fn validate_artifacts(artifacts: &[Artifact], targets: &[Target]) -> Result<(), String> {
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
pub(crate) fn parse_targets(text: &str) -> Result<Vec<Target>, String> {
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
