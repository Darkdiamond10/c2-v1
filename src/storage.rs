use std::path::PathBuf;
use std::fs;
use dirs;

pub fn get_storage_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    
    // Priority 1: Spotify Cache
    let spotify = home.join(".cache/spotify/Storage");
    if spotify.exists() {
        return Some(spotify.join("data.blob"));
    }
    
    // Priority 2: Firefox
    let mozilla = home.join(".mozilla/firefox");
    if mozilla.exists() {
        if let Ok(entries) = fs::read_dir(&mozilla) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && path.to_string_lossy().contains(".default-release") {
                    let cache = path.join("startupCache");
                    if cache.exists() {
                        return Some(cache.join("scriptCache.bin"));
                    }
                }
            }
        }
    }
    
    Some(home.join(".local/share/gvfs-metadata/home"))
}

pub fn read_blob(path: &PathBuf) -> Result<Vec<u8>, std::io::Error> {
    fs::read(path)
}

pub fn write_blob(path: &PathBuf, data: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data)
}
