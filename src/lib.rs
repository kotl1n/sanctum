pub mod bridge;
pub mod demo;
pub mod gateway;
pub mod json;
pub mod local_command;
pub mod model_boundary;
pub mod prompt_guard;
pub mod protocol;
pub mod redaction;
pub mod setup;
pub mod tool_guard;
pub mod vault;

use std::fmt;

/// Errors deliberately contain static codes, never input, credentials or URLs.
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
