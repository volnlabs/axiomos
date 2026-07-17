//! rkBPF Deployment CLI
//!
//! A command-line tool for managing, signing, and deploying BPF programs
//! for the rkBPF robotics kernel subsystem.

mod commands;
mod config;
mod signing;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;

#[derive(Parser)]
#[command(name = "rk")]
#[command(author = "rkBPF Team")]
#[command(version = "0.1.0")]
#[command(about = "rkBPF deployment and management CLI", long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Key management commands
    #[command(subcommand)]
    Key(KeyCommands),

    /// Sign a BPF program
    Sign {
        /// Input BPF object file (.o)
        #[arg(short, long)]
        input: String,

        /// Output signed program file (.rbpf)
        #[arg(short, long)]
        output: Option<String>,

        /// Private key file for signing
        #[arg(short, long)]
        key: String,
    },

    /// Verify a signed BPF program
    Verify {
        /// Signed program file (.rbpf)
        #[arg(short, long)]
        input: String,

        /// Public key file for verification
        #[arg(short, long)]
        key: Option<String>,

        /// Trusted keys directory
        #[arg(short, long)]
        trusted_dir: Option<String>,
    },

    /// Build a BPF program from source
    Build {
        /// Source file or directory
        #[arg(short, long)]
        source: String,

        /// Output directory
        #[arg(short, long)]
        output: Option<String>,

        /// Target profile (cloud or embedded)
        #[arg(short, long, default_value = "embedded")]
        profile: String,
    },

    /// Deploy a signed program to a device
    Deploy {
        /// Signed program file(s)
        #[arg(short, long)]
        program: Vec<String>,

        /// Target device (e.g., localhost, ssh://user@host)
        #[arg(short, long, default_value = "localhost")]
        target: String,

        /// Program attach point
        #[arg(short, long)]
        attach: Option<String>,
    },

    /// List loaded programs
    List {
        /// Target device
        #[arg(short, long, default_value = "localhost")]
        target: String,
    },

    /// Unload a program
    Unload {
        /// Program ID or name
        #[arg(short, long)]
        program: String,

        /// Target device
        #[arg(short, long, default_value = "localhost")]
        target: String,
    },

    /// Show program info
    Info {
        /// BPF object file or signed program
        #[arg(short, long)]
        input: String,
    },

    /// Initialize a new rkBPF project
    Init {
        /// Project name
        name: String,

        /// Target profile
        #[arg(short, long, default_value = "embedded")]
        profile: String,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Generate a new Ed25519 keypair
    Generate {
        /// Output file prefix (creates <prefix>.pub and <prefix>.key)
        #[arg(short, long)]
        output: String,
    },

    /// Export public key in various formats
    Export {
        /// Key file to export
        #[arg(short, long)]
        key: String,

        /// Output format (pem, der, raw)
        #[arg(short, long, default_value = "pem")]
        format: String,
    },

    /// Import a public key
    Import {
        /// Key file to import
        #[arg(short, long)]
        key: String,

        /// Alias for the key
        #[arg(short, long)]
        alias: String,
    },

    /// List trusted keys
    List,
}

fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    if cli.verbose {
        println!("{}", "rkBPF CLI v0.1.0".cyan().bold());
    }

    match cli.command {
        Commands::Key(key_cmd) => match key_cmd {
            KeyCommands::Generate { output } => commands::key::generate(&output),
            KeyCommands::Export { key, format } => commands::key::export(&key, &format),
            KeyCommands::Import { key, alias } => commands::key::import(&key, &alias),
            KeyCommands::List => commands::key::list(),
        },
        Commands::Sign { input, output, key } => {
            commands::sign::sign_program(&input, output.as_deref(), &key)
        }
        Commands::Verify {
            input,
            key,
            trusted_dir,
        } => commands::verify::verify_program(&input, key.as_deref(), trusted_dir.as_deref()),
        Commands::Build {
            source,
            output,
            profile,
        } => commands::build::build_program(&source, output.as_deref(), &profile),
        Commands::Deploy {
            program,
            target,
            attach,
        } => commands::deploy::deploy_programs(&program, &target, attach.as_deref()),
        Commands::List { target } => commands::list::list_programs(&target),
        Commands::Unload { program, target } => commands::unload::unload_program(&program, &target),
        Commands::Info { input } => commands::info::show_info(&input),
        Commands::Init { name, profile } => commands::init::init_project(&name, &profile),
    }
}
