use std::collections::HashMap;
use std::sync::Arc;

use oo7::Keyring;
use tracing::{debug, instrument, warn};

use crate::error::{Error, Result};

/// Attributes used to identify SSH key items in the Secret Service.
const ATTR_TYPE: &str = "type";
const ATTR_TYPE_VALUE: &str = "ssh-key";
const ATTR_FINGERPRINT: &str = "fingerprint";
const ATTR_COMMENT: &str = "comment";
const ATTR_ALGORITHM: &str = "algorithm";
const ATTR_SCHEMA: &str = "xdg:schema";
const ATTR_SCHEMA_VALUE: &str = "org.freedesktop.Secret.Generic";

/// Metadata for a stored SSH key, extracted from Secret Service item attributes.
#[derive(Debug, Clone)]
pub struct SshKeyMeta {
    pub fingerprint: String,
    pub comment: String,
    pub algorithm: String,
}

/// Thin wrapper around `oo7::Keyring` scoped to SSH key operations.
///
/// This does NOT parse SSH keys or compute fingerprints — that belongs in `keys.rs`.
/// This module only deals with storing, retrieving, and deleting opaque byte blobs
/// identified by string attributes.
#[derive(Clone)]
pub struct SshKeyring {
    inner: Arc<Keyring>,
}

impl SshKeyring {
    /// Connect to the default Secret Service collection.
    pub async fn new() -> Result<Self> {
        let keyring = Keyring::new().await?;
        Ok(Self {
            inner: Arc::new(keyring),
        })
    }

    /// List metadata for all SSH keys in the keyring.
    ///
    /// Does NOT fetch secret material — only reads attributes.
    #[instrument(skip(self))]
    pub async fn list_keys(&self) -> Result<Vec<SshKeyMeta>> {
        let items = self
            .inner
            .search_items(&[(ATTR_TYPE, ATTR_TYPE_VALUE)])
            .await?;

        let mut keys = Vec::with_capacity(items.len());
        for item in &items {
            let attrs = item.attributes().await?;
            if let Some(meta) = extract_meta(&attrs) {
                keys.push(meta);
            } else {
                warn!("skipping SSH key item with incomplete attributes");
            }
        }

        debug!(count = keys.len(), "listed SSH keys");
        Ok(keys)
    }

    /// Fetch the raw secret bytes for the SSH key matching `fingerprint`.
    ///
    /// Returns the `oo7::Secret` directly — it implements `ZeroizeOnDrop`,
    /// so the caller doesn't need to worry about cleanup.
    #[instrument(skip(self))]
    pub async fn get_secret(&self, fingerprint: &str) -> Result<oo7::Secret> {
        let items = self
            .inner
            .search_items(&[(ATTR_TYPE, ATTR_TYPE_VALUE), (ATTR_FINGERPRINT, fingerprint)])
            .await?;

        let item = items
            .into_iter()
            .next()
            .ok_or_else(|| Error::KeyNotFound(fingerprint.to_string()))?;

        Ok(item.secret().await?)
    }

    /// Store an SSH key in the keyring.
    ///
    /// `secret` is the raw OpenSSH private key bytes (PEM or binary).
    /// If a key with the same fingerprint already exists, it is replaced.
    #[instrument(skip(self, secret))]
    pub async fn store_key(
        &self,
        secret: impl Into<oo7::Secret>,
        fingerprint: &str,
        comment: &str,
        algorithm: &str,
    ) -> Result<()> {
        let label = format!("SSH key: {comment}");

        self.inner
            .create_item(
                &label,
                &[
                    (ATTR_SCHEMA, ATTR_SCHEMA_VALUE),
                    (ATTR_TYPE, ATTR_TYPE_VALUE),
                    (ATTR_FINGERPRINT, fingerprint),
                    (ATTR_COMMENT, comment),
                    (ATTR_ALGORITHM, algorithm),
                ],
                secret,
                true, // replace existing
            )
            .await?;

        debug!(fingerprint, comment, "stored SSH key");
        Ok(())
    }

    /// Delete all SSH keys matching `fingerprint`.
    #[instrument(skip(self))]
    pub async fn delete_key(&self, fingerprint: &str) -> Result<()> {
        self.inner
            .delete(&[(ATTR_TYPE, ATTR_TYPE_VALUE), (ATTR_FINGERPRINT, fingerprint)])
            .await?;

        debug!(fingerprint, "deleted SSH key");
        Ok(())
    }

    /// Delete all SSH keys from the keyring.
    #[instrument(skip(self))]
    pub async fn delete_all_keys(&self) -> Result<()> {
        self.inner
            .delete(&[(ATTR_TYPE, ATTR_TYPE_VALUE)])
            .await?;

        debug!("deleted all SSH keys");
        Ok(())
    }

    /// Check if the backing collection is locked.
    pub async fn is_locked(&self) -> Result<bool> {
        Ok(self.inner.is_locked().await?)
    }

    /// Unlock the backing collection.
    ///
    /// This triggers whatever prompt the Secret Service daemon is configured
    /// with (pinentry, portal, etc.). The caller should enforce a timeout
    /// around this call.
    pub async fn unlock(&self) -> Result<()> {
        self.inner.unlock().await?;
        Ok(())
    }

    /// Lock the backing collection.
    pub async fn lock(&self) -> Result<()> {
        self.inner.lock().await?;
        Ok(())
    }
}

/// Extract SSH key metadata from item attributes, returning `None` if
/// any required attribute is missing.
fn extract_meta(attrs: &HashMap<String, String>) -> Option<SshKeyMeta> {
    Some(SshKeyMeta {
        fingerprint: attrs.get(ATTR_FINGERPRINT)?.clone(),
        comment: attrs.get(ATTR_COMMENT)?.clone(),
        algorithm: attrs.get(ATTR_ALGORITHM)?.clone(),
    })
}
