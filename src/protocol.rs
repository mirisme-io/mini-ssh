use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Messages sent from the client to the server
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClientMessage {
    AuthenticatePassword {
        username: String,
        password: String, // Send raw password for server verification and key derivation
    },
    AuthenticateCertificate {
        username: String,
    }, // Initial cert auth request
    AuthChallengeResponse { signature: Vec<u8> }, // Client sends signature of challenge
    ExecuteCommand {
        command: String,
        args: Vec<String>,
    },
    ChangeDirectory { path: String },
    GetCurrentDirectory,
    ListDirectory { path: Option<String> }, // Path relative to current dir or absolute
    GetEnvironment,
    SetEnvironment { key: String, value: String },
    Disconnect,
    // Add other message types as needed (e.g., file transfer, interactive commands)
}

/// Messages sent from the server to the client
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ServerMessage {
    AuthenticationResult {
        success: bool,
        message: String,
        salt: Option<Vec<u8>>, // Salt for password-based key derivation
    },
    AuthChallenge { challenge: Vec<u8> }, // Server sends challenge for client to sign
    PublicKey { public_key_pem: String }, // Server sends its public key for secure channel setup or cert auth
    CommandOutput { stdout: String, stderr: String, exit_code: Option<i32> },
    DirectoryListing { entries: Vec<String>, error: Option<String> },
    CurrentDirectory { path: String },
    EnvironmentVariables { vars: HashMap<String, String> },
    Acknowledge,
    Error { message: String },
    // Add other message types as needed
}

// Helper function to serialize messages
pub fn serialize_message<T: Serialize>(msg: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(msg).map_err(|e| e.to_string())
}

// Helper function to deserialize messages
pub fn deserialize_message<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T, String> {
    serde_json::from_slice(data).map_err(|e| e.to_string())
}