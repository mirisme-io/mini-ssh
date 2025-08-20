use anyhow::{Context, Result, bail};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Version
};
use ed25519_dalek::{
    Signer, Verifier, SigningKey, VerifyingKey, Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH
};
use log::{debug, error, info, warn};
use pem::parse;
use pkcs8::{SubjectPublicKeyInfoRef, der::Decode as DerDecode, DecodePrivateKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use sha2::{Sha256, Digest};
use byteorder::{BigEndian, ReadBytesExt};

// --- User Store ---

#[derive(Clone, Debug)]
pub enum AuthMethod {
    PasswordHash(String),
    PublicKey(VerifyingKey),
}

#[derive(Clone, Debug)]
pub struct UserStore {
    users: Arc<StdMutex<HashMap<String, AuthMethod>>>,
}

impl UserStore {
    pub fn new() -> Self {
        Self {
            users: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    pub fn add_user(&mut self, username: String, method: AuthMethod) {
        let mut users = self.users.lock().expect("User store mutex poisoned");
        info!("Adding user '{}' with method {:?}", username, method);
        users.insert(username, method);
    }

    pub fn get_auth_method(&self, username: &str) -> Option<AuthMethod> {
        let users = self.users.lock().expect("User store mutex poisoned");
        users.get(username).cloned()
    }

    pub fn user_count(&self) -> usize {
        self.users.lock().expect("User store mutex poisoned").len()
    }

    pub fn load_test_users(&mut self) {
        match hash_password("password123") {
            Ok(hash) => self.add_user("user_pass".to_string(), AuthMethod::PasswordHash(hash)),
            Err(e) => error!("Failed to hash test user password: {}", e),
        }

        match load_public_key_from_file("test_user_cert.pub") {
            Ok(pub_key) => self.add_user("user_cert".to_string(), AuthMethod::PublicKey(pub_key)),
            Err(e) => warn!("Failed to load test user public key (test_user_cert.pub): {}. Cert auth may fail.", e),
        }
    }
}

// --- Password Hashing --- //

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        argon2::Params::default(),
    );

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?
        .to_string();

    Ok(password_hash)
}

pub fn verify_password(password: &str, password_hash_str: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(password_hash_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse password hash: {}", e))?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("Password verification error: {}", e)),
    }
}

// --- Session Key Derivation ---

// Derive a 32-byte session key from the password and a salt using Argon2.
// Use different parameters or context than password hashing if possible,
// but using the same algorithm is acceptable here.
pub fn derive_session_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        argon2::Params::new(15000, 2, 1, Some(32)).map_err(|e| anyhow::anyhow!("Argon2 KDF params failed: {}", e))? // Slightly different params for KDF
    );

    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Failed to derive session key: {}", e))?;

    Ok(key)
}

// Generates a random salt suitable for key derivation
pub fn generate_kdf_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

// --- Certificate / Key Handling ---
const ED25519_OID: pkcs8::ObjectIdentifier = pkcs8::ObjectIdentifier::new_unwrap("1.3.101.112");

// Load Ed25519 private key from PEM file
pub fn load_private_key(path: &Path) -> Result<SigningKey> {
    let pem_content = fs::read(path)
        .with_context(|| format!("Failed to read private key file: {:?}", path))?;
    let key_pem = parse(&pem_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM content from file {:?}: {}", path, e))?;

    // Try parsing as PKCS#8 DER first, as it's a common standard format for private keys.
    match SigningKey::from_pkcs8_der(key_pem.contents()) {
        Ok(signing_key) => {
            debug!("Successfully parsed private key from {:?} as PKCS#8 DER.", path);
            return Ok(signing_key);
        }
        Err(e_pkcs8) => {
            warn!("Failed to parse private key from {:?} as PKCS#8 DER: {}. Trying raw formats.", path, e_pkcs8);
            // Fall through to try raw formats if PKCS#8 parsing fails
        }
    }

    // Try raw 32-byte seed or 64-byte keypair (common for Ed25519 if not PKCS#8)
    let contents = key_pem.contents();
    if contents.len() == 32 {
        debug!("Attempting to parse private key from {:?} as raw 32-byte seed.", path);
        Ok(SigningKey::from_bytes(contents.try_into().map_err(|_| anyhow::anyhow!("PEM content not 32 bytes for seed"))?))
    } else if contents.len() == 64 {
        debug!("Attempting to parse private key from {:?} as raw 64-byte keypair.", path);
        let kp_bytes: [u8; 64] = contents.try_into()
            .map_err(|_| anyhow::anyhow!("PEM content is not 64 bytes for keypair"))?;
        Ok(SigningKey::from_keypair_bytes(&kp_bytes)?)
    } else {
        bail!(
            "Private key file {:?} (tag: {}) has unrecognized content length: {}. \
            Expected PKCS#8 DER, or raw 32 (seed) or 64 (keypair) bytes.",
            path, key_pem.tag(), contents.len()
        );
    }
}

// Load Ed25519 public key from PEM file (or OpenSSH format)
pub fn load_public_key_from_file(path: &str) -> Result<VerifyingKey> {
    let key_content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read public key file: {}", path))?;

    if key_content.starts_with("-----BEGIN PUBLIC KEY-----") {
        let key_pem = parse(&key_content)
             .map_err(|e| anyhow::anyhow!("Failed to parse public key PEM: {}", e))?;
        if key_pem.tag() != "PUBLIC KEY" {
             bail!("Unsupported PEM tag '{}' for public key", key_pem.tag());
        }
        let spki = SubjectPublicKeyInfoRef::from_der(key_pem.contents())
            .map_err(|e| anyhow::anyhow!("Failed to parse SubjectPublicKeyInfo from DER: {}", e))?;

        if spki.algorithm.oid != ED25519_OID {
            bail!("Public key is not Ed25519 (OID mismatch: got {}, expected {})", spki.algorithm.oid, ED25519_OID);
        }

        let public_key_bytes = spki.subject_public_key.raw_bytes();
        if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
            bail!("Extracted Ed25519 public key has incorrect length: {} != {}", public_key_bytes.len(), PUBLIC_KEY_LENGTH);
        }

        VerifyingKey::from_bytes(public_key_bytes.try_into().unwrap()) // unwrap safe due to length check
             .map_err(|e| anyhow::anyhow!("Failed to create VerifyingKey from SPKI bytes: {}", e))

    }
    else if key_content.starts_with("ssh-ed25519 ") {
        let parts: Vec<&str> = key_content.split_whitespace().collect();
        if parts.len() < 2 {
            bail!("Invalid OpenSSH public key format (not enough parts)");
        }
        let base64_key = parts[1];
        use base64::{engine::general_purpose::STANDARD as base64_engine, Engine as _};
        let decoded_bytes = base64_engine.decode(base64_key)
            .map_err(|e| anyhow::anyhow!("Failed to decode base64 public key: {}", e))?;

        let mut cursor = std::io::Cursor::new(decoded_bytes);
        
        let id_len = cursor.read_u32::<BigEndian>().context("Failed to read OpenSSH key id length")? as usize;
        if cursor.position() + id_len as u64 > cursor.get_ref().len() as u64 {
            bail!("OpenSSH key identifier length exceeds buffer (id_len: {}, buffer_len: {}, pos: {})", 
                id_len, cursor.get_ref().len(), cursor.position());
        }
        let mut id_buf = vec![0u8; id_len];
        cursor.read_exact(&mut id_buf).context("Failed to read OpenSSH key identifier")?;
        if String::from_utf8_lossy(&id_buf) != "ssh-ed25519" {
            bail!("OpenSSH key identifier is not 'ssh-ed25519', got: {}", String::from_utf8_lossy(&id_buf));
        }

        let key_len = cursor.read_u32::<BigEndian>().context("Failed to read OpenSSH public key length")? as usize;
        if key_len != PUBLIC_KEY_LENGTH {
            bail!("OpenSSH public key length is not {} (got {})", PUBLIC_KEY_LENGTH, key_len);
        }
        if cursor.position() + key_len as u64 > cursor.get_ref().len() as u64 {
            bail!("OpenSSH public key data length exceeds buffer (key_len: {}, buffer_len: {}, pos: {})",
                key_len, cursor.get_ref().len(), cursor.position());
        }
        let mut key_bytes_arr = [0u8; PUBLIC_KEY_LENGTH];
        cursor.read_exact(&mut key_bytes_arr).context("Failed to read OpenSSH public key data")?;
        
        VerifyingKey::from_bytes(&key_bytes_arr)
            .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key bytes from OpenSSH format: {}", e))

    } else {
        bail!("Unrecognized public key file format in {}. Expected PEM (-----BEGIN PUBLIC KEY-----) or OpenSSH (ssh-ed25519 ...).", path);
    }
}

// Sign a challenge (byte slice) using the private key
pub fn sign_challenge(signing_key: &SigningKey, challenge: &[u8]) -> Result<Signature> {
    debug!("Signing challenge data ({} bytes)", challenge.len());
    Ok(signing_key.sign(challenge))
}

// Verify a signature against a challenge and public key
pub fn verify_signature(verifying_key: &VerifyingKey, challenge: &[u8], signature_bytes: &[u8]) -> Result<bool> {
     debug!("Verifying signature for challenge ({} bytes)", challenge.len());
     if signature_bytes.len() != SIGNATURE_LENGTH {
          warn!("Received signature of incorrect length: {} != {}", signature_bytes.len(), SIGNATURE_LENGTH);
          return Ok(false);
     }
     let signature = Signature::from_bytes(signature_bytes.try_into().map_err(|_| anyhow::anyhow!("Signature byte array has incorrect length for Ed25519"))?);
     match verifying_key.verify(challenge, &signature) {
         Ok(_) => Ok(true),
         Err(e) => {
            warn!("Signature verification failed: {}",e);
            Ok(false) // Signature mismatch is a verification failure, not an operational error.
         }
     }
}

// --- Session Key Derivation (Certificate) ---

// Derive a 32-byte session key from the signature using SHA-256.
// This is simple but less standard than HKDF or deriving from a shared secret (e.g., DH).
pub fn derive_session_key_from_signature(signature_bytes: &[u8]) -> Result<[u8; 32]> {
    if signature_bytes.len() < 32 {
        bail!("Signature is too short ({} bytes) to derive a 32-byte key", signature_bytes.len());
    }
    let mut hasher = Sha256::new();
    hasher.update(signature_bytes);
    let hash_result = hasher.finalize();
    Ok(hash_result.into())
}

// --- Authentication Logic (Server-side) --- //

pub async fn handle_password_auth(
    username: &str,
    password_attempt: &str,
    user_store: &UserStore,
) -> Result<bool> {
    debug!("Attempting password auth for user: {}", username);

    let auth_method = match user_store.get_auth_method(username) {
        Some(method) => method,
        None => {
            debug!("User '{}' not found in store.", username);
            return Ok(false);
        }
    };

    match auth_method {
        AuthMethod::PasswordHash(stored_hash) => {
            verify_password(password_attempt, &stored_hash)
                .map_err(|e| {
                     error!("Password verification internal error for user '{}': {}", username, e);
                     e
                })
        }
        AuthMethod::PublicKey(_) => {
            warn!("User '{}' tried password auth, but is configured for public key auth.", username);
            Ok(false)
        }
    }
}

// --- Authentication Messages (Placeholder) --- //

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthRequest {
    pub username: String,
    pub method: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
}