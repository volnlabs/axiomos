use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::{env, fs};

const COMPONENT_MANIFEST: &str = "ci/components.toml";
const GENERATED_COMPONENTS: &str = "docs/generated/components.md";

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

fn check_or_write_docs(root: &Path, components: &[Component], check: bool) -> Result<(), String> {
    let expected = render_components(components);
    let path = root.join(GENERATED_COMPONENTS);
    if check {
        let actual = fs::read_to_string(&path)
            .map_err(|e| format!("{}: {e}; run `cargo xtask docs`", path.display()))?;
        if actual != expected {
            return Err(format!(
                "{} is stale; run `cargo xtask docs`",
                path.display()
            ));
        }
    } else {
        fs::write(&path, expected).map_err(|e| format!("{}: {e}", path.display()))?;
        println!("updated {}", path.display());
    }
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
}
