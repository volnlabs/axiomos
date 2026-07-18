//! Project initialization command.

use std::fs;
use std::path::Path;

use anyhow::Result;
use colored::Colorize;

/// Initialize a new rkBPF project.
pub fn init_project(name: &str, profile: &str) -> Result<()> {
    println!(
        "{} {} ({} profile)",
        "Initializing project".cyan().bold(),
        name.green(),
        profile.yellow()
    );

    let project_dir = Path::new(name);

    if project_dir.exists() {
        anyhow::bail!("Directory '{}' already exists", name);
    }

    // Create directory structure
    fs::create_dir_all(project_dir.join("src"))?;
    fs::create_dir_all(project_dir.join("include"))?;
    fs::create_dir_all(project_dir.join("keys"))?;

    println!("  {} Created directory structure", "".green());

    // Create rkbpf.toml configuration
    let config = format!(
        r#"# rkBPF Project Configuration
[project]
name = "{name}"
version = "0.1.0"
profile = "{profile}"

[build]
# Source directory for BPF programs
src = "src"
# Output directory for compiled objects
output = "target/bpf"

[signing]
# Private key for signing (generate with 'rk key generate')
# key = "keys/dev.key"

[deploy]
# Default deployment target
target = "localhost"
"#,
        name = name,
        profile = profile
    );

    fs::write(project_dir.join("rkbpf.toml"), config)?;
    println!("  {} Created rkbpf.toml", "".green());

    // Create example BPF program
    let example_program = format!(
        r#"// {name} - rkBPF Program
// Profile: {profile}

#include <rkbpf/types.h>
#include <rkbpf/helpers.h>

// Simple program that returns a constant
SEC("socket")
int main_prog(void *ctx) {{
    return 0;
}}

char _license[] SEC("license") = "GPL";
"#,
        name = name,
        profile = profile
    );

    fs::write(project_dir.join("src/main.bpf.c"), example_program)?;
    println!("  {} Created src/main.bpf.c", "".green());

    // Create basic include header
    let types_header = r#"#ifndef RKBPF_TYPES_H
#define RKBPF_TYPES_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

#define SEC(name) __attribute__((section(name), used))

#endif /* RKBPF_TYPES_H */
"#;

    fs::create_dir_all(project_dir.join("include/rkbpf"))?;
    fs::write(project_dir.join("include/rkbpf/types.h"), types_header)?;

    let helpers_header = r#"#ifndef RKBPF_HELPERS_H
#define RKBPF_HELPERS_H

#include "types.h"

// BPF helper function definitions
// These are provided by the kernel at runtime

static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;
static long (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static long (*bpf_ktime_get_ns)(void) = (void *) 5;

// rkBPF-specific helpers
static long (*rkbpf_motor_stop)(__u32 motor_id) = (void *) 1000;
static long (*rkbpf_gpio_read)(__u32 pin) = (void *) 1001;
static long (*rkbpf_timeseries_push)(__u32 map_id, __u64 timestamp, __u64 value) = (void *) 1002;

#endif /* RKBPF_HELPERS_H */
"#;

    fs::write(project_dir.join("include/rkbpf/helpers.h"), helpers_header)?;
    println!("  {} Created include files", "".green());

    // Create .gitignore
    let gitignore = r#"# Build artifacts
target/
*.o
*.rbpf

# Keys (keep public, ignore private)
keys/*.key

# Editor files
*.swp
*~
.vscode/
.idea/
"#;

    fs::write(project_dir.join(".gitignore"), gitignore)?;
    println!("  {} Created .gitignore", "".green());

    // Create README
    let readme = format!(
        r#"# {name}

An rkBPF program for the {profile} profile.

## Building

```bash
cd {name}
rk build -s src -p {profile}
```

## Signing

First, generate a keypair:

```bash
rk key generate -o keys/dev
```

Then sign the program:

```bash
rk sign -i target/bpf/main.o -k keys/dev.key
```

## Deploying

```bash
rk deploy -p main.rbpf -t localhost
```

## Project Structure

```
{name}/
├── rkbpf.toml      # Project configuration
├── src/            # BPF source files
│   └── main.bpf.c  # Main program
├── include/        # Header files
│   └── rkbpf/
├── keys/           # Signing keys
└── target/         # Build output
    └── bpf/
```
"#,
        name = name,
        profile = profile
    );

    fs::write(project_dir.join("README.md"), readme)?;
    println!("  {} Created README.md", "".green());

    println!("\n{} Project initialized!", "".green().bold());
    println!("\nNext steps:");
    println!("  cd {}", name.cyan());
    println!("  rk key generate -o keys/dev");
    println!("  rk build -s src");
    println!("  rk sign -i target/bpf/main.o -k keys/dev.key");

    Ok(())
}
