pub mod broker;
pub mod event;
pub mod gateway;
pub mod ledger;
pub mod merkle;
pub mod policy;
pub mod runlog;
pub mod sandbox;
pub mod secrets;
pub mod sensor;

use std::fmt;

/// Every error names the action to take, because the reader is an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    pub cause: String,
    pub fix: String,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}. Fix: {}", self.cause, self.fix)
    }
}

impl std::error::Error for Fault {}

impl Fault {
    pub fn new(cause: impl Into<String>, fix: impl Into<String>) -> Self {
        Fault {
            cause: cause.into(),
            fix: fix.into(),
        }
    }
}
