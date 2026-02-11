//! Error types for deSnark.

use displaydoc::Display;

/// Errors for the deSnark protocol.
#[derive(Display, Debug)]
pub enum DeSnarkError {
    // TODO: define error variants
}

impl std::error::Error for DeSnarkError {}

