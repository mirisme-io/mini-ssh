use crate::protocol::{ClientMessage, ServerMessage, serialize_message, deserialize_message};
use aes_gcm::aead::{Aead, Nonce, Payload, AeadCore};
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use anyhow::{Context, Result, bail};
use log::debug;
use rand::rngs::OsRng;
use rand::RngCore;
use typenum::Unsigned;
use std::io::ErrorKind;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;

pub struct SecureConnection {
    writer: Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
    reader: Arc<Mutex<BufReader<OwnedReadHalf>>>,
    cipher: Arc<Aes256Gcm>,
}

impl SecureConnection {
    pub fn new(reader_half: OwnedReadHalf, writer_half: OwnedWriteHalf, session_key: Key<Aes256Gcm>) -> Self {
        let reader = Arc::new(Mutex::new(BufReader::new(reader_half)));
        let writer = Arc::new(Mutex::new(BufWriter::new(writer_half)));
        let cipher = Arc::new(Aes256Gcm::new(&session_key));

        debug!("SecureConnection initialized with derived session key.");

        Self {
            writer,
            reader,
            cipher,
        }
    }

    pub async fn send_message(&self, msg: &ClientMessage) -> Result<()> {
        let serialized = serialize_message(msg).map_err(anyhow::Error::msg)?;
        self.write_encrypted(&serialized).await
    }

    pub async fn receive_message(&self) -> Result<ClientMessage> {
        let decrypted = self.read_encrypted().await?;
        let msg: ClientMessage = deserialize_message(&decrypted).map_err(anyhow::Error::msg)?;
        Ok(msg)
    }

    pub async fn send_server_message(&self, msg: &ServerMessage) -> Result<()> {
        let serialized = serialize_message(msg).map_err(anyhow::Error::msg)?;
        self.write_encrypted(&serialized).await
    }

    pub async fn receive_server_message(&self) -> Result<ServerMessage> {
        let decrypted = self.read_encrypted().await?;
        let msg: ServerMessage = deserialize_message(&decrypted).map_err(anyhow::Error::msg)?;
        Ok(msg)
    }

    async fn write_encrypted(&self, data: &[u8]) -> Result<()> {
        let nonce_bytes = Self::generate_nonce();
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, Payload { msg: data, aad: b"" })
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        let mut framed_message = Vec::new();
        framed_message.extend_from_slice(&nonce_bytes);
        framed_message.extend_from_slice(&ciphertext);

        let len = framed_message.len() as u32;

        let mut writer_guard = self.writer.lock().await;
        writer_guard.write_u32(len).await.context("Failed to write message length")?;
        writer_guard.write_all(&framed_message).await.context("Failed to write encrypted message")?;
        writer_guard.flush().await.context("Failed to flush writer")?;
        Ok(())
    }

    async fn read_encrypted(&self) -> Result<Vec<u8>> {
        let mut reader_guard = self.reader.lock().await;
        let len = match reader_guard.read_u32().await {
            Ok(l) => l,
            Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => {
                bail!(std::io::Error::new(ErrorKind::UnexpectedEof, "Connection closed while reading length"));
            }
            Err(e) => return Err(e).context("Failed to read message length"),
        };

        if len > 10 * 1024 * 1024 { // 10MB limit
             bail!("Encrypted message length {} exceeds limit", len);
        }

        let mut framed_message = vec![0u8; len as usize];
        match reader_guard.read_exact(&mut framed_message).await {
             Ok(_) => {},
             Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => {
                 bail!(std::io::Error::new(ErrorKind::UnexpectedEof, "Connection closed while reading message payload"));
            }
            Err(e) => return Err(e).context("Failed to read encrypted message payload"),
        };

        let nonce_size = <Aes256Gcm as AeadCore>::NonceSize::to_usize();
        if framed_message.len() < nonce_size {
            bail!("Received message is too short to contain a nonce ({} < {})", framed_message.len(), nonce_size);
        }

        let (nonce_bytes, ciphertext) = framed_message.split_at(nonce_size);
        let nonce = Nonce::<Aes256Gcm>::from_slice(nonce_bytes);

        let decrypted = self.cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad: b"" })
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(decrypted)
    }

    fn generate_nonce() -> [u8; 12] {
        let mut rng = OsRng;
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        nonce_bytes
    }
} 