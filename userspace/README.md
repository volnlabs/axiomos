# Userspace Components

Userspace is grouped by shipped role while crate package names remain stable:

- `core/`: the init process, minimal runtime library, and root-filesystem model.
- `tools/`: host or guest control-plane loaders, runtime-kit tools, and bridges.
- `demos/`: executable examples and integration probes; not production tools.
- `benchmarks/`: measurement workloads and verifier calibration drivers.

The exact workspace and rootfs disposition of every crate is declared in
[`ci/manifests/components.toml`](../ci/manifests/components.toml). Directory
grouping does not by itself promote a demo or benchmark into a shipped product
surface.
