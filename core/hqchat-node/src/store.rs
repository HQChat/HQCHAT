//! A `Store` on the file system, for the bot: one file per blob under a
//! directory, written through a temporary file and a rename.

use std::fs;
use std::path::{Path, PathBuf};

use hqchat_engine::{Store, StoreError};

pub struct DirStore {
    root: PathBuf,
}

impl DirStore {
    pub fn new(root: impl Into<PathBuf>) -> std::io::Result<Self> {
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
            match entry.file_type() {
                Ok(t) if t.is_dir() => self.walk(&entry.path(), &key, out),
                Ok(_) => out.push(key),
                Err(_) => {}
            }
        }
    }
}

impl Store for DirStore {
    fn get(&self, key: String) -> Option<Vec<u8>> {
        fs::read(self.path(&key)?).ok()
    }

    fn put(&self, key: String, value: Vec<u8>) -> Result<(), StoreError> {
        let path = self
            .path(&key)
            .ok_or_else(|| StoreError::Write(format!("bad key {key}")))?;
        let dir = path.parent().expect("a key has a parent: the root");
        fs::create_dir_all(dir).map_err(|e| StoreError::Write(e.to_string()))?;
        let tmp = dir.join(format!(
            ".tmp-{}",
            path.file_name().expect("a file").to_string_lossy()
        ));
        fs::write(&tmp, &value)
            .and_then(|()| fs::rename(&tmp, &path))
            .map_err(|e| StoreError::Write(e.to_string()))
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
