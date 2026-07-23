use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use yxorp::config::ConfigSnapshot;
use yxorp::control::Supervisor;
use yxorp::l4;
use yxorp::telemetry;

#[derive(Debug, Parser)]
#[command(name = "yxorp", version, about = "Linux-first edge reverse proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(short, long, default_value = "/etc/yxorp/yxorp.toml")]
        config: PathBuf,
    },
    Check {
        #[arg(short, long)]
        config: PathBuf,
    },
    PrintEffectiveConfig {
        #[arg(short, long)]
        config: PathBuf,
    },
    PrintL4Plan {
        #[arg(short, long)]
        config: PathBuf,
    },
}

#[actix::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve { config } => {
            let snapshot = Arc::new(ConfigSnapshot::load(&config)?);
            telemetry::init_tracing(snapshot.config.telemetry.json_tracing);
            Supervisor::run(config, snapshot).await?;
        }
        Command::Check { config } => {
            let snapshot = ConfigSnapshot::load(&config)?;
            telemetry::init_tracing(snapshot.config.telemetry.json_tracing);
            println!("ok");
        }
        Command::PrintEffectiveConfig { config } => {
            let snapshot = ConfigSnapshot::load(&config)?;
            telemetry::init_tracing(snapshot.config.telemetry.json_tracing);
            println!("{}", toml::to_string_pretty(&snapshot.config)?);
        }
        Command::PrintL4Plan { config } => {
            let snapshot = ConfigSnapshot::load(&config)?;
            telemetry::init_tracing(snapshot.config.telemetry.json_tracing);
            print!("{}", l4::render_config_plan(&snapshot.config));
        }
    }

    Ok(())
}
