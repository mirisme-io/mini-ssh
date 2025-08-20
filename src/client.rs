use anyhow::{Result, Context, bail};
use clap::Parser;
use log::{info, error, debug};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use aes_gcm::{Aes256Gcm, Key};
use std::path::PathBuf;

use ssh:: {
    secure_connection::SecureConnection,
    client_ui::ClientUI,
    protocol::{ClientMessage, ServerMessage, serialize_message, deserialize_message},
    auth::{derive_session_key, load_private_key, sign_challenge, derive_session_key_from_signature},
    repl::Repl,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Server address (e.g., 127.0.0.1)
    #[arg(short, long)]
    server: String,

    /// Server port
    #[arg(short, long, default_value_t = 2222)]
    port: u16,

    /// Authentication mode (password or certificate)
    #[arg(short = 'm', long, value_parser = ["password", "certificate"], default_value="password")]
    auth_mode: String,

    /// Username
    #[arg(short, long)]
    username: String,

    /// Private key file path (for certificate auth)
    #[arg(short = 'i', long, required_if_eq("auth_mode", "certificate"))]
    identity_file: Option<PathBuf>,
}

// Helper to send a message over raw stream (before encryption)
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

// Helper to receive a message over raw stream (before encryption)
async fn receive_raw_message<T: serde::de::DeserializeOwned>(
    reader: &mut BufReader<OwnedReadHalf>
) -> Result<T> {
    let len = reader.read_u32().await.context("Failed to read raw message length")?;
    // Add a reasonable size limit for raw messages
    if len > 1024 * 1024 { // 1MB limit for auth messages
        bail!("Raw message length {} exceeds limit", len);
    }
    let mut buffer = vec![0u8; len as usize];
    reader.read_exact(&mut buffer).await.context("Failed to read raw message data")?;
    let msg: T = deserialize_message(&buffer).map_err(anyhow::Error::msg)?;
    Ok(msg)
}

async fn run_client(args: Args) -> Result<()> {
    info!("Connecting to {}:{} as user '{}' using {} auth mode",
        args.server, args.port, args.username, args.auth_mode);
    if args.auth_mode == "certificate" {
        info!("Using identity file: {:?}", args.identity_file.as_ref().unwrap_or(&PathBuf::new()));
    }

    let stream = TcpStream::connect(format!("{}:{}", args.server, args.port))
        .await
        .with_context(|| format!("Failed to connect to server {}:{}", args.server, args.port))?;
    info!("TCP connection established. Authenticating...");

    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);

    let session_key: Key<Aes256Gcm>;

    match args.auth_mode.as_str() {
        "password" => {
            let password = ClientUI::get_password(&format!("Password for {}@{}: ", args.username, args.server))
                .context("Failed to get password interactively")?;
            
            let auth_req_msg = ClientMessage::AuthenticatePassword {
                username: args.username.clone(),
                password: password.clone(),
            };
            send_raw_message(&mut writer, &auth_req_msg).await.context("Failed to send password auth request")?;

            debug!("Waiting for password authentication result...");
            let auth_result: ServerMessage = receive_raw_message(&mut reader).await
                .context("Failed to receive auth result for password auth")?;

            match auth_result {
                ServerMessage::AuthenticationResult { success: true, message, salt: Some(salt_vec) } => {
                    info!("Password authentication successful: {}", message);
                    let key_bytes = derive_session_key(&password, &salt_vec).context("Failed to derive session key")?;
                    session_key = Key::<Aes256Gcm>::from_slice(&key_bytes).clone();
                }
                ServerMessage::AuthenticationResult { success: true, message: _, salt: None } => {
                     error!("Password authentication succeeded but server did not provide a salt for key derivation.");
                     bail!("Server configuration error during password authentication.");
                 }
                ServerMessage::AuthenticationResult { success: false, message, .. } => {
                    error!("Password authentication failed: {}", message);
                    bail!("Password authentication failed: {}", message);
                }
                other => {
                    error!("Received unexpected message during password authentication: {:?}", other);
                    bail!("Unexpected message during password authentication");
                }
            }
        }
        "certificate" => {
            let identity_file_path = args.identity_file.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Identity file is required for certificate authentication but should have been guaranteed by clap"))?;
            
            info!("Loading private key from: {:?}", identity_file_path);
            let signing_key = load_private_key(identity_file_path)
                .with_context(|| format!("Failed to load private key from {:?}", identity_file_path))?;

            let auth_req_msg = ClientMessage::AuthenticateCertificate { username: args.username.clone() };
            send_raw_message(&mut writer, &auth_req_msg).await.context("Failed to send certificate auth request")?;

            debug!("Waiting for auth challenge from server...");
            let challenge_msg: ServerMessage = receive_raw_message(&mut reader).await
                .context("Failed to receive auth challenge for certificate auth")?;

            match challenge_msg {
                ServerMessage::AuthChallenge { challenge } => {
                    debug!("Received challenge ({} bytes), signing...", challenge.len());
                    let signature = sign_challenge(&signing_key, &challenge)
                        .context("Failed to sign challenge")?;
                    
                    let response_msg = ClientMessage::AuthChallengeResponse { signature: signature.to_bytes().to_vec() };
                    send_raw_message(&mut writer, &response_msg).await.context("Failed to send challenge response")?;

                    debug!("Waiting for certificate authentication result...");
                    let auth_result: ServerMessage = receive_raw_message(&mut reader).await
                        .context("Failed to receive auth result for certificate auth")?;

                    match auth_result {
                        ServerMessage::AuthenticationResult { success: true, message, salt: None } => { 
                            info!("Certificate authentication successful: {}", message);
                            let key_bytes = derive_session_key_from_signature(&signature.to_bytes())
                                .context("Failed to derive session key from signature")?;
                            session_key = Key::<Aes256Gcm>::from_slice(&key_bytes).clone();
                        }
                        ServerMessage::AuthenticationResult { success: false, message, .. } => { 
                            error!("Certificate authentication failed: {}", message);
                            bail!("Certificate authentication failed: {}", message);
                        }
                        other => {
                            error!("Received unexpected message during certificate authentication result phase: {:?}", other);
                            bail!("Unexpected message during certificate authentication result phase");
                        }
                    }
                }
                ServerMessage::AuthenticationResult { success: false, message, .. } => { 
                    error!("Certificate authentication failed early: {}", message);
                    bail!("Certificate authentication failed: {}", message);
                }
                other => {
                    error!("Received unexpected message while waiting for auth challenge: {:?}", other);
                    bail!("Unexpected message while waiting for auth challenge");
                }
            }
        }
        _ => {
             error!("Unsupported authentication mode: {}", args.auth_mode);
             bail!("Internal error: Unsupported authentication mode '{}' encountered", args.auth_mode);
        }
    };

    info!("Secure connection to be established. Initializing REPL...");
    let connection = SecureConnection::new(reader.into_inner(), writer.into_inner(), session_key);
    let mut repl = Repl::new(connection).context("Failed to initialize REPL")?;
    repl.run().await.context("REPL failed")
}

#[tokio::main]
async fn main() -> Result<()> {
    // for logging messages
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    debug!("Client arguments: {:?}", args);

    if let Err(e) = run_client(args).await {
        error!("Client error: {:?}", e);
        eprintln!("Error: {}", e.root_cause()); // Print root cause for user
        std::process::exit(1);
    }

    Ok(())
}
