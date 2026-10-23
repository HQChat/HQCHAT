//! A `Store` on the file system, for the bot: one file per blob under a
//! directory, written through a temporary file, synced, then renamed, so a
//! crash leaves the old blob or the new one and never half of either. Files
//! are readable by their owner only.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use hqchat_engine::{Store, StoreError};

pub struct DirStore {
    root: PathBuf,
}

impl DirStore {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Keys are the engine's own (`state`, `session/…`, `msg/…/…`): every
    /// segment is hex, digits or a word, never `..`.
    fn path(&self, key: &str) -> Option<PathBuf> {
        let ok = !key.is_empty()
            && key.split('/').all(|s| {
                !s.is_empty()
                    && s != "."
                    && s != ".."
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
        ok.then(|| self.root.join(key))
    }

    fn walk(&self, dir: &Path, prefix: &str, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".tmp-") {
                continue;
            }
            let key = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            // Symlinks are neither: nothing the store wrote points elsewhere.
            match entry.file_type() {
                Ok(t) if t.is_dir() => self.walk(&entry.path(), &key, out),
                Ok(t) if t.is_file() => out.push(key),
                _ => {}
            }
        }
    }
}

impl Store for DirStore {
    fn get(&self, key: String) -> Option<Vec<u8>> {
        fs::read(self.path(&key)?).ok()
    }

    fn put(&self, key: String, value: Vec<u8>) -> Result<(), StoreError> {
        let bad_key = || StoreError::Write(format!("bad key {key}"));
        let path = self.path(&key).ok_or_else(bad_key)?;
        let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(bad_key());
        };
        let tmp = dir.join(format!(".tmp-{}", name.to_string_lossy()));
        write_durably(dir, &tmp, &path, &value).map_err(|e| StoreError::Write(e.to_string()))
    }

    fn delete(&self, key: String) {
        if let Some(path) = self.path(&key) {
            let _ = fs::remove_file(path);
        }
    }

    fn list(&self, prefix: String) -> Vec<String> {
        let mut out = Vec::new();
        self.walk(&self.root, "", &mut out);
        out.retain(|k| k.starts_with(&prefix));
        out.sort();
        out
    }
}

/// Writes `value` to `tmp`, syncs it, renames it over `path`, then syncs
/// the directory so the rename itself survives a power cut.
fn write_durably(dir: &Path, tmp: &Path, path: &Path, value: &[u8]) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(tmp)?;
    file.write_all(value)?;
    file.sync_all()?;
    fs::rename(tmp, path)?;
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}
