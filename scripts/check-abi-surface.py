#!/usr/bin/env python3
"""Verify that the published ABI catalog matches shipped dispatch code."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def catalog_section(catalog: str, name: str, next_name: str) -> str:
    return catalog.split(f"pub const {name}", 1)[1].split(
        f"pub const {next_name}", 1
    )[0]


def entries(section: str, prefix: str) -> set[str]:
    return set(re.findall(rf"entry!\(\s*({prefix}[A-Z0-9_]+)", section))


def require_equal(label: str, expected: set[str], actual: set[str]) -> None:
    if expected != actual:
        missing = sorted(expected - actual)
        unpublished = sorted(actual - expected)
        raise SystemExit(
            f"{label} catalog drift: missing from dispatch={missing}, "
            f"missing from catalog={unpublished}"
        )


def main() -> None:
    catalog = source("kernel/crates/kernel_abi/src/catalog.rs")

    syscall_catalog = entries(
        catalog_section(catalog, "SUPPORTED_SYSCALLS", "SUPPORTED_BPF_COMMANDS"),
        "SYS_",
    )
    syscall_dispatch = source("kernel/src/syscall/mod.rs").split("match n", 1)[1]
    syscall_dispatch = syscall_dispatch.split("let result = match result", 1)[0]
    dispatched_syscalls = set(
        re.findall(r"kernel_abi::(SYS_[A-Z0-9_]+)\s*=>", syscall_dispatch)
    )
    require_equal("syscall", syscall_catalog, dispatched_syscalls)

    command_catalog = entries(
        catalog_section(
            catalog, "SUPPORTED_BPF_COMMANDS", "SUPPORTED_BPF_MAP_TYPES"
        ),
        "BPF_",
    )
    bpf_dispatch = source("kernel/src/syscall/bpf.rs").split("match cmd_u32 {", 1)[1]
    dispatched_commands = set(
        re.findall(
            r"^        (?:kernel_abi::)?(BPF_[A-Z0-9_]+)\s*=>",
            bpf_dispatch,
            re.MULTILINE,
        )
    )
    dispatched_commands.discard("BPF_BENCH_EXEC")
    require_equal("BPF command", command_catalog, dispatched_commands)

    map_catalog = entries(
        catalog_section(
            catalog, "SUPPORTED_BPF_MAP_TYPES", "SUPPORTED_BPF_ATTACH_TYPES"
        ),
        "BPF_MAP_TYPE_",
    )
    manager = source("kernel/src/bpf/mod.rs")
    create_map = manager.split("pub fn create_map_for", 1)[1].split(
        "let id = self.register_user_map", 1
    )[0]
    creatable_maps = set(re.findall(r"^            (BPF_MAP_TYPE_[A-Z0-9_]+)\s*=>", create_map, re.MULTILINE))
    require_equal("BPF map type", map_catalog, creatable_maps)

    attach_catalog = entries(
        catalog_section(
            catalog, "SUPPORTED_BPF_ATTACH_TYPES", "SUPPORTED_BPF_HELPERS"
        ),
        "BPF_ATTACH_TYPE_",
    )
    attach_catalog = {name.removeprefix("BPF_") for name in attach_catalog}
    supported_attach = manager.split("const fn is_supported_attach_type", 1)[1].split(
        "const fn is_latency_sensitive_attach_type", 1
    )[0]
    accepted_attach = set(re.findall(r"ATTACH_TYPE_[A-Z0-9_]+", supported_attach))
    require_equal("BPF attach type", attach_catalog, accepted_attach)

    helper_catalog = entries(
        catalog.split("pub const SUPPORTED_BPF_HELPERS", 1)[1], "BPF_HELPER_"
    )
    helper_source = source("kernel/crates/kernel_bpf/src/verifier/helpers.rs")
    variant_constants = dict(
        re.findall(
            r"^\s*(\w+) = abi::(BPF_HELPER_[A-Z0-9_]+),",
            helper_source,
            re.MULTILINE,
        )
    )
    runtime_helpers = helper_source.split("const fn runtime_helper", 1)[1].split(
        "const fn helper_signature", 1
    )[0]
    dispatched_variants = set(
        re.findall(r"HelperId::(\w+)\s*=>\s*Some\(RuntimeHelper::", runtime_helpers)
    )
    dispatched_helpers = {variant_constants[variant] for variant in dispatched_variants}
    require_equal("BPF helper", helper_catalog, dispatched_helpers)

    minilib = source("userspace/minilib/src/lib.rs")
    raw_wrappers = re.findall(r"syscall[0-4]\(\s*\d+", minilib)
    if raw_wrappers:
        raise SystemExit(f"minilib contains raw syscall wrapper numbers: {raw_wrappers}")

    print(
        "ABI surface clean: "
        f"{len(syscall_catalog)} syscalls, {len(command_catalog)} BPF commands, "
        f"{len(map_catalog)} maps, {len(helper_catalog)} helpers, "
        f"{len(attach_catalog)} attach types"
    )


if __name__ == "__main__":
    main()
