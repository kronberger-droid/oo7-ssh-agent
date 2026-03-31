use std::env;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::net::UnixListener;
use tracing::{debug, info};

/// The fd number systemd passes for the first socket (SD_LISTEN_FDS_START).
const SD_LISTEN_FDS_START: i32 = 3;

/// Determine the default socket path: `$XDG_RUNTIME_DIR/oo7-ssh-agent.sock`.
pub fn default_socket_path() -> Result<PathBuf> {
    let runtime_dir = env::var("XDG_RUNTIME_DIR")
        .context("XDG_RUNTIME_DIR not set — cannot determine default socket path")?;
    Ok(PathBuf::from(runtime_dir).join("oo7-ssh-agent.sock"))
}

/// Create a `UnixListener`, using socket activation if available,
/// otherwise binding to `path`.
///
/// When systemd socket-activates the service, `LISTEN_FDS=1` is set
/// and the socket fd is inherited as fd 3. In that case `path` is
/// ignored — systemd already created and bound the socket.
pub fn bind(path: &Path) -> Result<UnixListener> {
    if let Some(listener) = try_socket_activation()? {
        return Ok(listener);
    }

    bind_new(path)
}

/// Check for systemd socket activation via `LISTEN_FDS`.
fn try_socket_activation() -> Result<Option<UnixListener>> {
    let listen_fds: i32 = match env::var("LISTEN_FDS") {
        Ok(val) => val.parse().context("LISTEN_FDS is not a valid integer")?,
        Err(_) => return Ok(None),
    };

    if listen_fds < 1 {
        return Ok(None);
    }

    info!("using socket-activated fd (LISTEN_FDS={listen_fds})");

    // SAFETY: fd 3 is passed by systemd and is a valid, open socket.
    // We take ownership — systemd expects us to use it.
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(SD_LISTEN_FDS_START) };
    std_listener.set_nonblocking(true)?;
    Ok(Some(UnixListener::from_std(std_listener)?))
}

/// Bind a new Unix socket at `path` with mode 0o600.
fn bind_new(path: &Path) -> Result<UnixListener> {
    // Remove stale socket from a previous run.
    if path.exists() {
        debug!(path = %path.display(), "removing stale socket");
        std::fs::remove_file(path)
            .with_context(|| format!("failed to remove stale socket at {}", path.display()))?;
    }

    let listener = UnixListener::bind(path)
        .with_context(|| format!("failed to bind socket at {}", path.display()))?;

    // Restrict to owner only.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    info!(path = %path.display(), "listening on socket");
    Ok(listener)
}
