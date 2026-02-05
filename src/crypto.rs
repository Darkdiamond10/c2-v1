use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, Key, XNonce
};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, SaltString,
        Error
    },
    Argon2
};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::fs;
use std::path::Path;
use std::os::unix::fs::MetadataExt;
use obfstr::obfstr;

// SplitKey for Memory Hygiene
// The key never exists in memory as a whole until needed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SplitKey {
    part1: [u8; 32],
    part2: [u8; 32],
}

impl SplitKey {
    pub fn new(key: [u8; 32]) -> Self {
        let mut part1 = [0u8; 32];
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut part1);

        let mut part2 = [0u8; 32];
        for i in 0..32 {
            part2[i] = key[i] ^ part1[i];
        }

        SplitKey { part1, part2 }
    }
  impl SplitKey {
    pub fn new(key: [u8; 32]) -> Self {
        let mut part1 = [0u8; 32];
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut part1);

        let mut part2 = [0u8; 32];
        for i in 0..32 {
            part2[i] = key[i] ^ part1[i];
        }

        SplitKey { part1, part2 }
    }

    // Reconstructs the key only for the duration of the closure
    pub fn use_key<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; 32]) -> R,
    {
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = self.part1[i] ^ self.part2[i];
        }
        
        let result = f(&key);
        
        // Immediate wipe
        key.zeroize();
        result
    }
  }
  // Environmental Key Derivation
pub fn derive_env_key() -> Result<[u8; 32], String> {
    // 1. Machine ID
    let machine_id = fs::read_to_string("/etc/machine-id")
        .unwrap_or_else(|_| obfstr!("unknown_machine").to_string())
        .trim()
        .to_string();

    // 2. MAC Address (eth0 default)
    let mac_path = Path::new("/sys/class/net/eth0/address");
    let mac = if mac_path.exists() {
        fs::read_to_string(mac_path).unwrap_or_default().trim().to_string()
    } else {
        obfstr!("00:00:00:00:00:00").to_string()
    };

    // 3. Current User
    let user = std::env::var("USER").unwrap_or_else(|_| obfstr!("unknown_user").to_string());

    // 4. Inode of an immutable file
    let inode = fs::metadata("/etc/passwd")
        .map(|m| m.ino())
        .unwrap_or(0);

    // Combine Fingerprint
    let fingerprint = format!("{}{}{}{}", machine_id, mac, user, inode);
    
    // Salt (Hardcoded for this specific target instance)
    let salt = SaltString::generate(&mut OsRng); 
    
    // Argon2id
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(fingerprint.as_bytes(), &salt)
        .map_err(|e| e.to_string())?;
    
    let hash = password_hash.hash.ok_or("Hash failed")?;
    
    // Take first 32 bytes for the key
    let mut key_bytes = [0u8; 32];
    let len = std::cmp::min(hash.as_bytes().len(), 32);
    key_bytes[..len].copy_from_slice(&hash.as_bytes()[..len]);
    
    Ok(key_bytes)
}
  pub fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    
    let ciphertext = cipher.encrypt(&nonce, data)
        .map_err(|_| "Encryption failure")?;
        
    let mut result = nonce.to_vec();
    result.extend(ciphertext);
    Ok(result)
}

pub fn decrypt_data(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if data.len() < 24 {
        return Err("Data too short".to_string());
    }
    
    let nonce = XNonce::from_slice(&data[0..24]);
    let ciphertext = &data[24..];
    
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    
    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failure".to_string())
}
