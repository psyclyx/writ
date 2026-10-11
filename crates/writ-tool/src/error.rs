//! Errors and exit statuses: 0 yes, 1 no (a denial), 2 anything else.

use crate::args::Spec;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Bad command line.
    Usage {
        spec: &'static Spec,
        message: String,
    },
    /// `--help` was asked for.
    Help(&'static Spec),
    /// The answer is no; the explanation has been printed.
    Denied,
    /// Anything else.
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::Help(_) => 0,
            Error::Denied => 1,
            Error::Usage { .. } | Error::Msg(_) => 2,
        }
    }
}

/// `bail!("...")`-style constructor.
pub fn err<T>(message: impl fmt::Display) -> Result<T> {
    Err(Error::Msg(message.to_string()))
}

/// Adds context to foreign errors.
pub trait Context<T> {
    fn context(self, what: impl FnOnce() -> String) -> Result<T>;
}

impl<T, E: fmt::Display> Context<T> for std::result::Result<T, E> {
    fn context(self, what: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error::Msg(format!("{}: {e}", what())))
    }
}
