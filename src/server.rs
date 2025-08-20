use anyhow::{Result, Context, bail};
use clap::Parser;
use log::{info, error, warn, debug, trace};
use tokio::net::{TcpListener, TcpStream};
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command as TokioCommand;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use aes_gcm::{Aes256Gcm, Key};
use rand::rngs::OsRng;
use rand::RngCore;

use ssh:: {
    secure_connection::SecureConnection,
    protocol::{ClientMessage, ServerMessage, serialize_message, deserialize_message},
    auth::{UserStore, AuthMethod, handle_password_auth, derive_session_key, derive_session_key_from_signature, generate_kdf_salt, verify_signature},
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct ServerArgs {
    /// Listen address
    #[arg(short, long, default_value = "127.0.0.1")]
    address: String,

    /// Listen port
    #[arg(short, long, default_value_t = 2222)]
    port: u16,
}

struct ClientSession {
    username: String,
    current_dir: PathBuf,
    environment: HashMap<String, String>,
    connection: SecureConnection,
}

impl ClientSession {
    fn new(username: String, connection: SecureConnection) -> Result<Self> {
        Ok(Self {
            username,
            current_dir: env::current_dir().context("Failed to get server's initial current directory")?,
            environment: env::vars().collect(), // Initialize with server's environment
            connection,
        })
    }

    async fn handle_message(&mut self, msg: ClientMessage) -> Result<bool> { // bool indicates continue session
        trace!("User '{}' sent message: {:?}", self.username, msg);
        match msg {
            ClientMessage::AuthenticatePassword { .. } | ClientMessage::AuthenticateCertificate { .. } | ClientMessage::AuthChallengeResponse { .. } => {
                warn!("Received unexpected authentication-phase message after successful auth.");
                self.connection.send_server_message(&ServerMessage::Error { message: "Already authenticated".to_string() }).await?;
            }
            ClientMessage::ExecuteCommand { command, args } => {
                self.handle_execute_command(&command, &args).await?;
            }
            ClientMessage::ChangeDirectory { path } => {
                self.handle_change_directory(&path).await?;
            }
            ClientMessage::GetCurrentDirectory => {
                let path_str = self.current_dir.to_string_lossy().to_string();
                self.connection.send_server_message(&ServerMessage::CurrentDirectory { path: path_str }).await?;
            }
            ClientMessage::ListDirectory { path } => {
                self.handle_list_directory(path.as_deref()).await?;
            }
            ClientMessage::GetEnvironment => {
                self.connection.send_server_message(&ServerMessage::EnvironmentVariables { vars: self.environment.clone() }).await?;
            }
            ClientMessage::SetEnvironment { key, value } => {
                debug!("User '{}' setting env var: {}={}", self.username, key, value);
                self.environment.insert(key, value);
                self.connection.send_server_message(&ServerMessage::Acknowledge).await?;
            }
            ClientMessage::Disconnect => {
                info!("User '{}' requested disconnect.", self.username);
                return Ok(false); // Signal to end session
            }
        }
        Ok(true) // Continue session
    }

    async fn handle_execute_command(&mut self, command: &str, args: &[String]) -> Result<()> {
        info!("User '{}' executing command: {} {:?}", self.username, command, args);
        let mut cmd = TokioCommand::new(command);
        cmd.args(args)
           .current_dir(&self.current_dir)
           .envs(&self.environment)
           .stdin(Stdio::null()) // No interactive input yet
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        match cmd.spawn() {
            Ok(mut child) => {
                let stdout_handle = child.stdout.take();
                let stderr_handle = child.stderr.take();

                let stdout_task = tokio::spawn(async move {
                    let mut stdout_output = String::new();
                    if let Some(mut stdout_stream) = stdout_handle {
                        stdout_stream.read_to_string(&mut stdout_output).await.unwrap_or_default();
                    }
                    stdout_output
                });

                let stderr_task = tokio::spawn(async move {
                    let mut stderr_output = String::new();
                    if let Some(mut stderr_stream) = stderr_handle {
                         stderr_stream.read_to_string(&mut stderr_output).await.unwrap_or_default();
                    }
                     stderr_output
                });

                let status = child.wait().await.context("Failed to wait for command completion")?;
                let stdout = stdout_task.await.context("Stdout task failed")?;
                let stderr = stderr_task.await.context("Stderr task failed")?;

                self.connection.send_server_message(&ServerMessage::CommandOutput {
                    stdout,
                    stderr,
                    exit_code: status.code(),
                }).await?;
            }
            Err(e) => {
                warn!("Failed to execute command '{}': {}", command, e);
                let error_message = format!("Failed to execute command '{}': {}", command, e);
                self.connection.send_server_message(&ServerMessage::Error { message: error_message }).await?;
            }
        }
        Ok(())
    }

    async fn handle_change_directory(&mut self, path_str: &str) -> Result<()> {
        let new_path = if PathBuf::from(path_str).is_absolute() {
            PathBuf::from(path_str)
        } else {
            self.current_dir.join(path_str)
        };

        // Canonicalize to resolve '..' etc. and check existence
        match std::fs::canonicalize(&new_path) {
            Ok(canonical_path) => {
                if canonical_path.is_dir() {
                    debug!("User '{}' changed directory to: {:?}", self.username, canonical_path);
                    self.current_dir = canonical_path;
                    self.connection.send_server_message(&ServerMessage::Acknowledge).await?;
                } else {
                    let error_message = format!("cd: path is not a directory: {}", path_str);
                    warn!("{}", error_message);
                    self.connection.send_server_message(&ServerMessage::Error { message: error_message }).await?;
                }
            }
            Err(e) => {
                let error_message = format!("cd: failed to change directory to '{}': {}", path_str, e);
                 warn!("{}", error_message);
                self.connection.send_server_message(&ServerMessage::Error { message: error_message }).await?;
            }
        }
        Ok(())
    }

     async fn handle_list_directory(&mut self, path_opt: Option<&str>) -> Result<()> {
        let target_dir = match path_opt {
            Some(p) => {
                if PathBuf::from(p).is_absolute() {
                    PathBuf::from(p)
                } else {
                    self.current_dir.join(p)
                }
            }
            None => self.current_dir.clone(),
        };

        match std::fs::read_dir(&target_dir) {
            Ok(entries) => {
                let mut entry_names = Vec::new();
                for entry_result in entries {
                    match entry_result {
                        Ok(entry) => {
                            entry_names.push(entry.file_name().to_string_lossy().to_string());
                        }
                        Err(e) => {
                            warn!("Failed to read directory entry in {:?}: {}", target_dir, e);
                            // Optionally collect individual entry errors
                        }
                    }
                }
                entry_names.sort(); // Basic sort
                self.connection.send_server_message(&ServerMessage::DirectoryListing {
                    entries: entry_names,
                    error: None,
                }).await?;
            }
            Err(e) => {
                let error_message = format!("ls: cannot access '{}': {}", target_dir.display(), e);
                 warn!("{}", error_message);
                self.connection.send_server_message(&ServerMessage::DirectoryListing {
                    entries: vec![],
                    error: Some(error_message),
                }).await?;
            }
        }
        Ok(())
    }
}

async fn send_raw_message<T: serde::Serialize>(
    writer: &mut BufWriter<OwnedWriteHalf>,
    msg: &T
) -> Result<()> {
    let serialized = serialize_message(msg).map_err(anyhow::Error::msg)?;
    let len = serialized.len() as u32;
    writer.write_u32(len).await.context("Failed to write raw message length")?;
    writer.write_all(&serialized).await.context("Failed to write raw message data")?;
    writer.flush().await.context("Failed to flush raw message writer")?;
    Ok(())
}

async fn receive_raw_message<T: serde::de::DeserializeOwned>(
    reader: &mut BufReader<OwnedReadHalf>
) -> Result<T> {
    let len = reader.read_u32().await.context("Failed to read raw message length")?;
    if len > 1024 * 1024 { 
        bail!("Raw message length {} exceeds limit (1MB)", len);
    }
    let mut buffer = vec![0u8; len as usize];
    reader.read_exact(&mut buffer).await.context("Failed to read raw message data")?;
    let msg: T = deserialize_message(&buffer).map_err(anyhow::Error::msg)?;
    Ok(msg)
}

fn generate_challenge() -> [u8; 32] {
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    challenge
}

async fn handle_client(stream: TcpStream, user_store: UserStore) -> Result<()> {
    let peer_addr = stream.peer_addr().context("Failed to get peer address")?;
    info!("New client connection from: {:?}", peer_addr);

    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);

    let session_key: Key<Aes256Gcm>;
    let authenticated_user: String;

    debug!("Waiting for authentication message from {:?}...", peer_addr);
    let auth_message: ClientMessage = match receive_raw_message(&mut reader).await {
        Ok(msg) => msg,
        Err(e) => {
            error!("Failed to receive initial auth message from {:?}: {}", peer_addr, e);
            return Err(e);
        }
    };

    match auth_message {
        ClientMessage::AuthenticatePassword { username, password } => {
            debug!("Attempting password authentication for user '{}' from {:?}", username, peer_addr);
            match handle_password_auth(&username, &password, &user_store).await {
                Ok(true) => {
                    let salt = generate_kdf_salt();
                    match derive_session_key(&password, &salt) {
                        Ok(key_bytes) => {
                            session_key = Key::<Aes256Gcm>::from_slice(&key_bytes).clone();
                            authenticated_user = username.clone();
                    info!("Password authentication successful for user '{}' from {:?}", username, peer_addr);
                    send_raw_message(&mut writer, &ServerMessage::AuthenticationResult {
                        success: true,
                        message: "Password authentication successful".to_string(),
                                salt: Some(salt.to_vec()),
                            }).await.context("Failed to send password auth success")?;
                        }
                        Err(e) => {
                            error!("Failed to derive session key for user '{}': {}", username, e);
                            send_raw_message(&mut writer, &ServerMessage::AuthenticationResult {
                                success: false,
                                message: "Authentication failed (server error).".to_string(),
                                salt: None,
                            }).await.context("Failed to send auth failure (key derivation)")?;
                            bail!("Session key derivation failed for {}", username);
                        }
                    }
                }
                Ok(false) => {
                    warn!("Password authentication failed for user '{}' from {:?}", username, peer_addr);
                    send_raw_message(&mut writer, &ServerMessage::AuthenticationResult {
                        success: false,
                        message: "Invalid username or password.".to_string(),
                        salt: None,
                    }).await.context("Failed to send password auth failure")?;
                    bail!("Password auth failed for user {}", username);
                }
                Err(e) => {
                    error!("Error during password authentication for user '{}': {}", username, e);
                    send_raw_message(&mut writer, &ServerMessage::AuthenticationResult {
                        success: false,
                        message: "Authentication failed (server error).".to_string(),
                        salt: None,
                    }).await.context("Failed to send auth failure (internal error)")?;
                    return Err(e.context(format!("Password auth internal error for {}", username)));
                }
            }
        }
        ClientMessage::AuthenticateCertificate { username } => {
            debug!("Attempting certificate authentication for user '{}' from {:?}", username, peer_addr);
            match user_store.get_auth_method(&username) {
                Some(AuthMethod::PublicKey(verifying_key)) => {
                    let challenge = generate_challenge();
                    debug!("Sending challenge to user '{}' for certificate auth", username);
                    send_raw_message(&mut writer, &ServerMessage::AuthChallenge { challenge: challenge.to_vec() })
                        .await.context("Failed to send auth challenge")?;

                    debug!("Waiting for challenge response from user '{}'", username);
                    match receive_raw_message::<ClientMessage>(&mut reader).await {
                        Ok(ClientMessage::AuthChallengeResponse { signature }) => {
                            match verify_signature(&verifying_key, &challenge, &signature) {
                                Ok(true) => {
                                    match derive_session_key_from_signature(&signature) {
                                        Ok(key_bytes) => {
                                            session_key = Key::<Aes256Gcm>::from_slice(&key_bytes).clone();
                                            authenticated_user = username.clone();
                                            info!("Certificate authentication successful for user '{}' from {:?}", username, peer_addr);
            send_raw_message(&mut writer, &ServerMessage::AuthenticationResult {
                                                success: true,
                                                message: "Certificate authentication successful".to_string(),
                 salt: None,
                                            }).await.context("Failed to send cert auth success")?;
                                        }
                                        Err(e) => {
                                            error!("Failed to derive session key from signature for '{}': {}", username, e);
                                            send_raw_message(&mut writer, &ServerMessage::AuthenticationResult { 
                                                success: false, message: "Auth failed (key derivation error).".to_string(), salt: None 
                                            }).await.context("Failed to send cert auth key derivation failure")?;
                                            bail!("Session key derivation from signature failed for {}", username);
                                        }
                                    }
                                }
                                Ok(false) => {
                                    warn!("Certificate signature verification failed for user '{}' from {:?}", username, peer_addr);
                                    send_raw_message(&mut writer, &ServerMessage::AuthenticationResult { 
                                        success: false, message: "Invalid signature.".to_string(), salt: None 
                                    }).await.context("Failed to send cert auth signature failure")?;
                                    bail!("Certificate signature verification failed for {}", username);
                                }
                                Err(e) => {
                                    error!("Error during signature verification for '{}': {}", username, e);
                                    send_raw_message(&mut writer, &ServerMessage::AuthenticationResult { 
                                        success: false, message: "Auth failed (verification internal error).".to_string(), salt: None 
                                    }).await.context("Failed to send cert auth verification internal error failure")?;
                                    return Err(e.context(format!("Cert auth signature verification internal error for {}", username)));
                                }
                            }
                        }
                        Ok(other_msg) => {
                            warn!("User '{}' sent unexpected message {:?} during cert auth challenge phase.", username, other_msg);
            send_raw_message(&mut writer, &ServerMessage::AuthenticationResult {
                                success: false, message: "Unexpected message during auth.".to_string(), salt: None 
                            }).await.context("Failed to send cert auth unexpected message failure")?;
                            bail!("Unexpected message from {} during cert auth challenge: {:?}", username, other_msg);
                        }
                        Err(e) => {
                            error!("Failed to receive challenge response from '{}': {}", username, e);
                            // Don't send response here, connection likely dropped or malformed.
                            return Err(e.context(format!("Failed to receive challenge response from {}", username)));
                        }
                    }
                }
                Some(AuthMethod::PasswordHash(_)) => {
                    warn!("User '{}' attempted certificate auth, but is configured for password auth.", username);
                     send_raw_message(&mut writer, &ServerMessage::AuthenticationResult { 
                        success: false, message: "User configured for password authentication.".to_string(), salt: None 
                    }).await.context("Failed to send cert auth method mismatch failure")?;
                    bail!("User {} is configured for password auth, not certificate.", username);
                }
                None => {
                    warn!("User '{}' not found during certificate authentication attempt from {:?}.", username, peer_addr);
                    send_raw_message(&mut writer, &ServerMessage::AuthenticationResult { 
                        success: false, message: "User not found.".to_string(), salt: None 
                    }).await.context("Failed to send cert auth user not found failure")?;
                    bail!("User {} not found for certificate auth.", username);
                }
            }
        }
        ClientMessage::AuthChallengeResponse { .. } => {
            warn!("Received AuthChallengeResponse from {:?} unexpectedly (not in cert auth flow).", peer_addr);
            // Could send an error, but typically we'd just drop if state is wrong.
            bail!("Unexpected AuthChallengeResponse from {:?}", peer_addr);
        }
        // All other messages are handled after authentication
        _ => {
            error!("Received unexpected initial message type {:?} from {:?}. Expected auth message.", auth_message, peer_addr);
            send_raw_message(&mut writer, &ServerMessage::Error { message: "Invalid initial message. Expected authentication.".to_string() })
                .await.context("Failed to send invalid initial message error")?;
            bail!("Invalid initial message from {:?}: {:?}", peer_addr, auth_message);
        }
    }

    info!("Authentication complete for user '{}'. Initializing secure session...", authenticated_user);
    let secure_conn = SecureConnection::new(reader.into_inner(), writer.into_inner(), session_key);
    let mut client_session = ClientSession::new(authenticated_user.clone(), secure_conn)?;

    loop {
        match client_session.connection.receive_message().await {
            Ok(msg) => {
                if !client_session.handle_message(msg).await.unwrap_or_else(|e| {
                    error!("Error handling message for user '{}': {:?}. Terminating session.", client_session.username, e);
                    false // End session on error
                }) {
                    info!("Client session ended for user '{}'.", client_session.username);
                         break;
                 }
            }
            Err(e) => {
                if e.root_cause().is::<std::io::Error>() && 
                   e.root_cause().downcast_ref::<std::io::Error>().unwrap().kind() == std::io::ErrorKind::UnexpectedEof {
                    info!("Client '{}' disconnected (EOF).", client_session.username);
                } else {
                    error!("Error receiving message from user '{}': {:?}. Terminating session.", client_session.username, e);
                }
                break;
            }
        }
    }
    info!("Connection closed for user '{}' from {:?}", client_session.username, peer_addr);
    Ok(())
}

async fn run_server(args: ServerArgs, user_store: UserStore) -> Result<()> {
    let listener = TcpListener::bind(format!("{}:{}", args.address, args.port))
        .await
        .with_context(|| format!("Failed to bind to {}:{}", args.address, args.port))?;
    info!("Server listening on {}:{}", args.address, args.port);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let user_store_clone = user_store.clone(); // Clone for each client task
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, user_store_clone).await {
                        error!("Client handler error: {:?}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = ServerArgs::parse();

    // Initialize UserStore and add test users
    let mut user_store = UserStore::new();
    user_store.load_test_users(); 
    // In a real app, load users from a config file or database
    info!("User store initialized with {} users.", user_store.user_count());

    if let Err(e) = run_server(args, user_store).await {
        error!("Server error: {:?}", e);
        std::process::exit(1);
    }

    Ok(())
}