//! Persistence for the web config server's Noise_XX static identity.
//!
//! The static key authenticates the config server to clients (which pin its
//! public-key fingerprint), so it must survive restarts: a per-process key
//! would rotate the fingerprint on every restart and break pinned clients.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use easytier_core::tunnel::web_security::WebNoiseStaticKey;

/// Resolves the key file location: `<db_path>.noise-static-key`, with the
/// same URL normalization the sqlite layer applies to its own path.
/// Returns `None` for databases that cannot host a sibling file.
fn key_file_path(db_path: &str) -> Option<PathBuf> {
    let path = db_path
        .strip_prefix("sqlite://")
        .or_else(|| db_path.strip_prefix("sqlite:"))
        .unwrap_or(db_path);
    let path = path
        .strip_prefix("file:")
        .unwrap_or(path)
        .split('?')
        .next()?;
    if path.is_empty() || path == ":memory:" {
        return None;
    }
    Some(PathBuf::from(format!("{path}.noise-static-key")))
}

/// Loads the static noise key stored next to the database, generating and
/// persisting a fresh one on first start. Returns `None` only when the
/// database location cannot persist a key file (e.g. in-memory databases);
/// the server then stays on the legacy unauthenticated handshake.
pub fn load_or_generate(db_path: &str) -> anyhow::Result<Option<WebNoiseStaticKey>> {
    let Some(path) = key_file_path(db_path) else {
        return Ok(None);
    };
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes);
            return Ok(Some(WebNoiseStaticKey::from_secret_bytes(secret)));
        }
        Ok(bytes) => bail!(
            "corrupt noise static key file {}: expected 32 bytes, got {}",
            path.display(),
            bytes.len()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", path.display()));
        }
    }

    let key = WebNoiseStaticKey::random();
    // Write via temp + rename so a crash mid-write cannot leave a truncated
    // file that would silently rotate the server identity on next start.
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    std::fs::write(&tmp, key.secret_bytes()).with_context(|| format!("write {}", tmp.display()))?;
    restrict_permissions(&tmp)?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(Some(key))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db_path() -> String {
        std::env::temp_dir()
            .join(format!("et-noise-key-test-{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn generated_key_is_reloaded_unchanged() {
        let db_path = temp_db_path();
        let first = load_or_generate(&db_path).unwrap().expect("persisted key");
        let second = load_or_generate(&db_path).unwrap().expect("persisted key");
        assert_eq!(first.secret_bytes(), second.secret_bytes());
        assert_eq!(first.public_fingerprint(), second.public_fingerprint());
        let _ = std::fs::remove_file(format!("{db_path}.noise-static-key"));
    }

    #[test]
    fn in_memory_databases_have_no_key_file() {
        assert!(key_file_path(":memory:").is_none());
        assert!(load_or_generate(":memory:").unwrap().is_none());
        assert!(key_file_path("sqlite://et.db?mode=rw").is_some());
    }

    #[test]
    fn corrupt_key_files_fail_loudly() {
        let db_path = temp_db_path();
        std::fs::write(format!("{db_path}.noise-static-key"), [0u8; 7]).unwrap();
        assert!(load_or_generate(&db_path).is_err());
        let _ = std::fs::remove_file(format!("{db_path}.noise-static-key"));
    }
}
