use crate::{Error, Result};
use std::path::PathBuf;

pub fn home() -> Result<PathBuf> {
    #[cfg(windows)]
    let value = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"));
    #[cfg(not(windows))]
    let value = std::env::var_os("HOME");
    value
        .map(PathBuf::from)
        .ok_or(Error("home_directory_unavailable"))
}

pub fn executable(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

pub fn reparse_path(path: &std::path::Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        path.symlink_metadata()
            .is_ok_and(|metadata| metadata.file_attributes() & 0x400 != 0)
    }
    #[cfg(not(windows))]
    path.is_symlink()
}
