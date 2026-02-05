use libc::{c_char, c_void, c_int, c_ulong};
use std::ffi::CString;
use std::ptr;
use std::fs;
use obfstr::obfstr;

// Process Masquerading
pub fn mask_process(name: &str) {
    unsafe {
        let name_c = CString::new(name).unwrap();
        // prctl PR_SET_NAME
        libc::prctl(libc::PR_SET_NAME, name_c.as_ptr() as c_ulong, 0, 0, 0);
    }
}

// Memory Locking (Anti-Swap)
pub fn prevent_swap() -> Result<(), String> {
    unsafe {
        let ret = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
        if ret != 0 {
            return Err("mlockall failed".to_string());
        }
    }
    Ok(())
}

// Anti-Ptrace
pub fn anti_ptrace() {
    unsafe {
        let ret = libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
        if ret < 0 {
            std::process::exit(0); 
        }
    }
}

// Cleanup on Exit
pub fn install_crash_handler() {
    unsafe {
        let handler = cleanup_and_die as usize;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGQUIT, handler);
    }
}
extern "C" fn cleanup_and_die(_sig: c_int) {
    // Aggressive Heap Wiping
    if let Ok(maps) = fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            if line.contains("[heap]") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(range) = parts.get(0) {
                    let bounds: Vec<&str> = range.split('-').collect();
                    if bounds.len() == 2 {
                        let start = usize::from_str_radix(bounds[0], 16).unwrap_or(0);
                        let end = usize::from_str_radix(bounds[1], 16).unwrap_or(0);
                        let size = end - start;
                        
                        unsafe {
                            ptr::write_bytes(start as *mut u8, 0, size);
                        }
                    }
                }
            }
        }
    }
    unsafe { libc::exit(0); }
}
