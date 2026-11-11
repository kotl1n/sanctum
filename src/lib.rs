mod assignment;
pub mod bridge;
pub mod claude_hook;
pub mod cli;
mod context_paths;
pub mod gateway;
pub mod json;
pub mod local_arguments;
pub mod local_command;
pub mod model_boundary;
mod numeric;
pub mod opaque;
mod passwords;
mod patch_arguments;
pub mod platform;
pub mod preview;
pub mod prompt_guard;
pub mod protocol;
pub mod redaction;
pub mod rewrite;
pub mod settings;
pub mod setup;
mod tool_grammar;
pub mod tool_guard;
pub mod vault;
mod visual_json;
#[cfg(windows)]
mod windows;

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_BODY: usize = 8 * 1024 * 1024;
pub const MAX_EVENT: usize = 4 * 1024 * 1024;
pub mod context;
