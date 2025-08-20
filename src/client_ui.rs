// Potentially useful for future UI enhancements
use anyhow::{Result, Context};
use dialoguer::{Password};
use std::env; // Added for environment variable access

/// A simple UI for interacting with the user.
pub struct ClientUI;

impl ClientUI {
    /// Prompt the user for a password, or read from env var if set for testing.
    pub fn get_password(prompt: &str) -> Result<String> {
        // Check environment variable first (e.g., for non-interactive testing)
        if let Ok(password) = env::var("RUST_SSH_TEST_PASSWORD") {
            Ok(password)
        } else {
            // Fallback to interactive prompt if env var is not set
            Password::new()
                .with_prompt(prompt)
                .interact()
                .context("Failed to read password from terminal")
        }
    }

    // Add more UI methods here if needed (e.g., confirm, select)
}