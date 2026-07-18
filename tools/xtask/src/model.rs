use std::collections::BTreeMap;
use std::path::Path;

use crate::docs::load_build_inputs;
use crate::manifests::{
    load_artifacts, load_components, load_targets, Artifact, Component, Target,
};

#[derive(Debug)]
pub(crate) struct RepositoryModel {
    pub(crate) components: Vec<Component>,
    pub(crate) targets: Vec<Target>,
    pub(crate) artifacts: Vec<Artifact>,
    pub(crate) build_inputs: BTreeMap<String, String>,
}

impl RepositoryModel {
    pub(crate) fn load(root: &Path) -> Result<Self, String> {
        Ok(Self {
            components: load_components(root)?,
            targets: load_targets(root)?,
            artifacts: load_artifacts(root)?,
            build_inputs: load_build_inputs(root)?,
        })
    }
}
