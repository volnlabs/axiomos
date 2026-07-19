use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use crate::manifests::{parse_quoted, Component};

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

pub(crate) fn validate_inventory(root: &Path, components: &[Component]) -> Result<(), String> {
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

pub(crate) fn parse_workspace_array(text: &str, key: &str) -> Result<Vec<String>, String> {
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

pub(crate) fn validate_boundary_contract(
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

pub(crate) fn validate_boundary(root: &Path, components: &[Component]) -> Result<(), String> {
    let (members, excluded) = load_workspace_layout(root)?;
    let mut rootfs_executables = BTreeSet::new();
    collect_rootfs_executables(&file_structure::STRUCTURE, &mut rootfs_executables)?;
    validate_boundary_contract(components, &members, &excluded, &rootfs_executables)
}
