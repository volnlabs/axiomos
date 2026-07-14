use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::{env, fs};

const COMPONENT_MANIFEST: &str = "ci/components.toml";
const GENERATED_COMPONENTS: &str = "docs/generated/components.md";
const BUILD_INPUTS: &str = "ci/build-inputs.env";
const GENERATED_BUILD_INPUTS: &str = "docs/generated/build-inputs.md";
const TARGET_MANIFEST: &str = "ci/targets.toml";
const GENERATED_TARGETS: &str = "docs/generated/targets.md";
const GENERATED_ABI: &str = "docs/generated/abi.md";

#[derive(Debug, Clone, Eq, PartialEq)]
struct Component {
    path: String,
    kind: String,
    role: String,
    gate: String,
}

#[derive(Default)]
struct ComponentBuilder {
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Target {
    name: String,
    triple: String,
    status: String,
    features: String,
    artifact: String,
    evidence: String,
}

#[derive(Default)]
struct TargetBuilder {
    fields: BTreeMap<String, String>,
}

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
        })
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xtask must live under tools/xtask")
        .to_path_buf()
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
    parse_components(&text)
}

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
        if !matches!(key, "path" | "kind" | "role" | "gate") {
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
    parse_targets(&text)
}

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

fn render_components(components: &[Component]) -> String {
    let mut components = components.to_vec();
    components.sort_by(|a, b| a.path.cmp(&b.path));
    let mut output = String::from(
        "<!-- Generated by `cargo xtask docs`; do not edit. -->\n\n\
         # Component inventory\n\n\
         | Manifest | Kind | Role | Required gate |\n\
         |---|---|---|---|\n",
    );
    for component in components {
        output.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            component.path, component.kind, component.role, component.gate
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
        &render_targets(&load_targets(root)?),
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
    let status = Command::new(root.join("scripts/verify-engineering-audit.sh"))
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
        "Usage:\n  cargo xtask inventory --check\n  cargo xtask docs [--check]\n  cargo xtask ci [--quick|--full|--extended] [audit options]"
    );
}

fn execute() -> Result<(), String> {
    let root = repo_root();
    let components = load_components(&root)?;
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| "missing xtask command".to_owned())?;
    let remaining = args.collect::<Vec<_>>();

    match command.as_str() {
        "inventory" => {
            if remaining.iter().any(|arg| arg != "--check") {
                return Err("inventory accepts only --check".to_owned());
            }
            validate_inventory(&root, &components)?;
            println!(
                "component inventory: PASS ({} components)",
                components.len()
            );
            Ok(())
        }
        "docs" => {
            if remaining.iter().any(|arg| arg != "--check") {
                return Err("docs accepts only --check".to_owned());
            }
            validate_inventory(&root, &components)?;
            check_or_write_docs(
                &root,
                &components,
                remaining.iter().any(|arg| arg == "--check"),
            )
        }
        "ci" => {
            validate_inventory(&root, &components)?;
            check_or_write_docs(&root, &components, true)?;
            run_ci(&root, &remaining)
        }
        "help" | "--help" | "-h" => {
            usage();
            Ok(())
        }
        _ => Err(format!("unknown xtask command: {command}")),
    }
}

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            usage();
            ExitCode::FAILURE
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
}
