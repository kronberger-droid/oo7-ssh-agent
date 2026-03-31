mod agent;
mod error;
mod keyring;
mod keys;
mod socket;

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use ssh_agent_lib::agent::listen;
use tracing::info;
use tracing_subscriber::EnvFilter;

use agent::Oo7Session;
use keyring::SshKeyring;

#[derive(Parser)]
#[command(name = "oo7-ssh-agent", about = "SSH agent backed by org.freedesktop.secrets")]
struct Cli {
    /// Socket path. Defaults to $XDG_RUNTIME_DIR/oo7-ssh-agent.sock.
    /// Ignored when socket-activated by systemd.
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Unlock prompt timeout in seconds.
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Increase log verbosity (-v for debug, -vv for trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_tracing(cli.verbose);

    let socket_path = match &cli.socket {
        Some(path) => path.clone(),
        None => socket::default_socket_path()?,
    };

    let keyring = SshKeyring::new().await?;
    info!("connected to Secret Service");

    let session = Oo7Session::new(keyring, Duration::from_secs(cli.timeout));
    let listener = socket::bind(&socket_path)?;

    info!("agent ready");
    listen(listener, session)
        .await
        .map_err(|e: ssh_agent_lib::error::AgentError| anyhow::anyhow!(e))?;

    Ok(())
}

fn init_tracing(verbosity: u8) {
    let filter = match verbosity {
        0 => "warn",
        1 => "oo7_ssh_agent=debug,warn",
        _ => "oo7_ssh_agent=trace,debug",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .init();
}
