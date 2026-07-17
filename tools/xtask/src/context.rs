use std::env;
use std::path::{Path, PathBuf};

pub const COMPONENT_MANIFEST: &str = "ci/manifests/components.toml";
pub const GENERATED_COMPONENTS: &str = "docs/reference/generated/components.md";
pub const ARTIFACT_MANIFEST: &str = "ci/manifests/artifacts.toml";
pub const GENERATED_ARTIFACTS: &str = "docs/reference/generated/artifacts.md";
pub const BUILD_INPUTS: &str = "ci/manifests/build-inputs.env";
pub const GENERATED_BUILD_INPUTS: &str = "docs/reference/generated/build-inputs.md";
pub const TARGET_MANIFEST: &str = "ci/manifests/targets.toml";
pub const GENERATED_TARGETS: &str = "docs/reference/generated/targets.md";
pub const GENERATED_ABI: &str = "docs/reference/generated/abi.md";

#[must_use]
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xtask must live under tools/xtask")
        .to_path_buf()
}
