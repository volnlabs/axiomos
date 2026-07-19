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
    let error =
        validate_artifacts(&[artifact], &[target]).expect_err("mtime selection must be rejected");
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
