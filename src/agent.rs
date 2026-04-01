use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::message::{
    AddIdentity, Identity, RemoveIdentity, SignRequest,
};
use ssh_agent_lib::proto::Credential;
use ssh_key::{LineEnding, PrivateKey, Signature};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::keyring::SshKeyring;
use crate::keys;

/// Per-connection SSH agent session backed by the Secret Service keyring.
///
/// Each incoming Unix socket connection gets its own `Oo7Session`.
/// Since `SshKeyring` is cheaply cloneable (`Arc`), all sessions
/// share the same underlying keyring connection. The agent-level
/// lock state is also shared via `Arc`.
#[derive(Clone)]
pub struct Oo7Session {
    keyring: SshKeyring,
    /// Agent-level lock state, independent of the keyring's own lock.
    /// `None` = unlocked, `Some(passphrase)` = locked.
    /// SSH protocol requires UNLOCK to provide the same passphrase as LOCK.
    lock_passphrase: Arc<Mutex<Option<Zeroizing<String>>>>,
    /// Timeout for keyring unlock prompts (pinentry/portal).
    unlock_timeout: Duration,
    /// Shared timestamp of last activity, for idle timeout.
    last_activity: Arc<Mutex<Instant>>,
}

impl Oo7Session {
    pub fn new(keyring: SshKeyring, unlock_timeout: Duration) -> Self {
        Self {
            keyring,
            lock_passphrase: Arc::new(Mutex::new(None)),
            unlock_timeout,
            last_activity: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Returns the shared last-activity timestamp for idle timeout monitoring.
    pub fn last_activity(&self) -> Arc<Mutex<Instant>> {
        self.last_activity.clone()
    }

    /// Record activity to reset the idle timeout.
    fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    /// Check if the agent is locked. Returns `Err(AgentError::Failure)` if locked.
    fn check_agent_lock(&self) -> Result<(), AgentError> {
        if self.lock_passphrase.lock().unwrap().is_some() {
            return Err(AgentError::Failure);
        }
        Ok(())
    }

    /// Attempt to unlock the keyring collection if locked, with a timeout.
    async fn ensure_unlocked(&self) -> Result<(), AgentError> {
        if self.keyring.is_locked().await.map_err(AgentError::other)? {
            debug!("collection is locked, attempting unlock (timeout: {:?})", self.unlock_timeout);
            tokio::time::timeout(self.unlock_timeout, self.keyring.unlock())
                .await
                .map_err(|_| {
                    warn!("unlock prompt timed out after {:?}", self.unlock_timeout);
                    AgentError::Failure
                })?
                .map_err(AgentError::other)?;
        }
        Ok(())
    }
}

#[ssh_agent_lib::async_trait]
impl Session for Oo7Session {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        self.check_agent_lock()?;
        self.touch();

        if let Err(e) = self.ensure_unlocked().await {
            warn!(error = %e, "could not unlock collection, returning empty identity list");
            return Ok(vec![]);
        }

        let metas = self
            .keyring
            .list_keys()
            .await
            .map_err(AgentError::other)?;

        let mut identities = Vec::with_capacity(metas.len());
        for meta in &metas {
            match self.keyring.get_secret(&meta.fingerprint).await {
                Ok(secret) => {
                    let parse_result = keys::parse_private_key(secret.as_bytes());
                    drop(secret); // zeroize PEM bytes immediately
                    match parse_result {
                        Ok(privkey) => {
                            let identity = Identity {
                                pubkey: keys::public_key_data(&privkey),
                                comment: meta.comment.clone(),
                            };
                            drop(privkey);
                            identities.push(identity);
                        }
                        Err(e) => {
                            warn!(
                                fingerprint = %meta.fingerprint,
                                error = %e,
                                "skipping unparseable SSH key"
                            );
                        }
                    }
                },
                Err(e) => {
                    warn!(
                        fingerprint = %meta.fingerprint,
                        error = %e,
                        "skipping inaccessible SSH key"
                    );
                }
            }
        }

        debug!(count = identities.len(), "returning identities");
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        self.check_agent_lock()?;
        self.touch();
        self.ensure_unlocked().await?;

        let fingerprint = keys::fingerprint(&request.pubkey);
        debug!(fingerprint = %fingerprint, "sign request");

        let secret = self
            .keyring
            .get_secret(&fingerprint)
            .await
            .map_err(AgentError::other)?;

        let privkey = keys::parse_private_key(secret.as_bytes())
            .map_err(AgentError::other)?;
        drop(secret);

        let signature = keys::sign(&privkey, &request.data, request.flags)
            .map_err(AgentError::other)?;
        drop(privkey);

        debug!(fingerprint = %fingerprint, "sign request completed");
        Ok(signature)
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        self.check_agent_lock()?;
        self.touch();

        let Credential::Key { privkey, comment } = identity.credential else {
            warn!("certificate credentials are not supported");
            return Err(AgentError::Failure);
        };

        let privkey = PrivateKey::new(privkey, &comment)
            .map_err(AgentError::other)?;

        let pubkey_data = keys::public_key_data(&privkey);
        let fingerprint = keys::fingerprint(&pubkey_data);
        let algorithm = keys::algorithm_name(&pubkey_data);

        let openssh = privkey
            .to_openssh(LineEnding::LF)
            .map_err(AgentError::other)?;
        drop(privkey);

        // Pass as Zeroizing<Vec<u8>> so the intermediate buffer is zeroized.
        // oo7::Secret has From<Zeroizing<Vec<u8>>>.
        let openssh_bytes = Zeroizing::new(openssh.as_bytes().to_vec());
        drop(openssh);

        self.keyring
            .store_key(openssh_bytes, &fingerprint, &comment, algorithm)
            .await
            .map_err(AgentError::other)?;

        debug!(fingerprint = %fingerprint, comment = %comment, "added identity");
        Ok(())
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), AgentError> {
        self.check_agent_lock()?;
        self.touch();

        let fingerprint = keys::fingerprint(&identity.pubkey);

        self.keyring
            .delete_key(&fingerprint)
            .await
            .map_err(AgentError::other)?;

        debug!(fingerprint = %fingerprint, "removed identity");
        Ok(())
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        self.check_agent_lock()?;
        self.touch();

        self.keyring
            .delete_all_keys()
            .await
            .map_err(AgentError::other)?;

        debug!("removed all identities");
        Ok(())
    }

    async fn lock(&mut self, passphrase: String) -> Result<(), AgentError> {
        self.touch();
        let passphrase = Zeroizing::new(passphrase);
        let mut lock = self.lock_passphrase.lock().unwrap();
        if lock.is_some() {
            return Err(AgentError::Failure);
        }
        *lock = Some(passphrase);
        debug!("agent locked");
        Ok(())
    }

    async fn unlock(&mut self, passphrase: String) -> Result<(), AgentError> {
        self.touch();
        let passphrase = Zeroizing::new(passphrase);
        let mut lock = self.lock_passphrase.lock().unwrap();
        match lock.as_ref() {
            Some(stored) if stored.as_str() == passphrase.as_str() => {
                *lock = None;
                debug!("agent unlocked");
                Ok(())
            }
            Some(_) => {
                warn!("unlock failed: wrong passphrase");
                Err(AgentError::Failure)
            }
            None => Ok(()),
        }
    }
}
