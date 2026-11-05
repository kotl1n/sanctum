use std::path::{Path, PathBuf};

pub struct TempDir(PathBuf);
impl TempDir {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sanctum-test-{}",
            sanctum::setup::random_key().unwrap()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Cargo при кросс-компиляции в Linux встраивает путь Linux; Wine отображает его на Z:.
#[allow(dead_code)]
pub fn binary(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    #[cfg(windows)]
    {
        let mut path = if path.to_string_lossy().starts_with('/') {
            PathBuf::from(format!("Z:{}", path.to_string_lossy().replace('/', "\\")))
        } else {
            path.to_path_buf()
        };
        if path.extension().is_none() {
            path.set_extension("exe");
        }
        path
    }
    #[cfg(not(windows))]
    path.to_path_buf()
}
