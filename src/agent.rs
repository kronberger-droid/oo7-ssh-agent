use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::message::{
    AddIdentity, Identity, RemoveIdentity, SignRequest,
};
use ssh_agent_lib::proto::Credential;
use ssh_key::{LineEnding, PrivateKey, Signature};
use tracing::{debug, warn};

use crate::keyring::SshKeyring;
use crate::keys;

/// Per-connection SSH agent session backed by the Secret Service keyring.
///
/// Each incoming Unix socket connection gets its own `Oo7Session`.
/// Since `SshKeyring` is cheaply cloneable (`Arc`), all sessions
/// share the same underlying keyring connection.
#[derive(Clone)]
pub struct Oo7Session {
    keyring: SshKeyring,
}

impl Oo7Session {
    pub fn new(keyring: SshKeyring) -> Self {
        Self { keyring }
    }

    /// Attempt to unlock the collection if locked.
    /// Returns Ok(()) if already unlocked or successfully unlocked.
    async fn ensure_unlocked(&self) -> Result<(), AgentError> {
        if self.keyring.is_locked().await.map_err(AgentError::other)? {
            debug!("collection is locked, attempting unlock");
            self.keyring
                .unlock()
                .await
                .map_err(AgentError::other)?;
        }
        Ok(())
    }
}

#[ssh_agent_lib::async_trait]
impl Session for Oo7Session {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
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
                Ok(secret) => match keys::parse_private_key(secret.as_bytes()) {
                    Ok(privkey) => {
                        identities.push(Identity {
                            pubkey: keys::public_key_data(&privkey),
                            comment: meta.comment.clone(),
                        });
                    }
                    Err(e) => {
                        warn!(
                            fingerprint = %meta.fingerprint,
                            error = %e,
                            "skipping unparseable SSH key"
                        );
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
            // `secret` dropped here → oo7::Secret::ZeroizeOnDrop cleans up
        }

        debug!(count = identities.len(), "returning identities");
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
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
        // `secret` is still alive here but will be dropped at end of scope.
        // oo7::Secret zeroizes on drop automatically.

        let signature = keys::sign(&privkey, &request.data)
            .map_err(AgentError::other)?;
        // `privkey` dropped here. ssh_key::PrivateKey zeroizes key material.

        debug!(fingerprint = %fingerprint, "sign request completed");
        Ok(signature)
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
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

        self.keyring
            .store_key(openssh.as_bytes(), &fingerprint, &comment, algorithm)
            .await
            .map_err(AgentError::other)?;

        debug!(fingerprint = %fingerprint, comment = %comment, "added identity");
        Ok(())
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), AgentError> {
        let fingerprint = keys::fingerprint(&identity.pubkey);

        self.keyring
            .delete_key(&fingerprint)
            .await
            .map_err(AgentError::other)?;

        debug!(fingerprint = %fingerprint, "removed identity");
        Ok(())
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        self.keyring
            .delete_all_keys()
            .await
            .map_err(AgentError::other)?;

        debug!("removed all identities");
        Ok(())
    }

    async fn lock(&mut self, _passphrase: String) -> Result<(), AgentError> {
        // SSH agent LOCK takes a passphrase, but we delegate to the
        // Secret Service collection lock which has its own auth model.
        // The passphrase is ignored.
        self.keyring.lock().await.map_err(AgentError::other)?;
        debug!("locked collection");
        Ok(())
    }

    async fn unlock(&mut self, _passphrase: String) -> Result<(), AgentError> {
        // Same as lock — passphrase is ignored, unlock triggers
        // the Secret Service's own prompt (pinentry/portal).
        self.keyring.unlock().await.map_err(AgentError::other)?;
        debug!("unlocked collection");
        Ok(())
    }
}
