use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self { enabled: true }
    }
}
impl Settings {
    pub fn active(&self) -> bool {
        self.enabled
    }
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let mut value =
                    crate::json::parse(&bytes).map_err(|_| Error("invalid_settings"))?;
                if let Some(object) = value.as_object_mut() {
                    object.remove("force_disabled");
                }
                serde_json::from_value(value).map_err(|_| Error("invalid_settings"))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(_) => Err(Error("settings_read_failed")),
        }
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        let parent = path.parent().ok_or(Error("settings_path_required"))?;
        std::fs::create_dir_all(parent).map_err(|_| Error("settings_directory_failed"))?;
        let temp = parent.join(format!(".settings-{}", crate::setup::random_key()?));
        let result = (|| {
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temp)
                .map_err(|_| Error("settings_write_failed"))?;
            #[cfg(windows)]
            crate::windows::protect_path(&temp)?;
            file.write_all(
                &serde_json::to_vec_pretty(self).map_err(|_| Error("settings_encode_failed"))?,
            )
            .and_then(|_| file.sync_all())
            .map_err(|_| Error("settings_write_failed"))?;
            std::fs::rename(&temp, path).map_err(|_| Error("settings_commit_failed"))
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temp);
        }
        result
    }
}
pub fn path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("SANCTUM_SETTINGS_PATH") {
        return Ok(path.into());
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| crate::platform::home().ok().map(|h| h.join(".config")))
        .ok_or(Error("home_directory_unavailable"))?;
    Ok(base.join("sanctum-portless/settings.json"))
}
pub fn active() -> bool {
    try_active().unwrap_or(false)
}

pub fn try_active() -> Result<bool> {
    path().and_then(|p| Settings::load(&p)).map(|s| s.active())
}
