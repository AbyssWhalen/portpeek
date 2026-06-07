#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

use crate::model::PortEntry;

/// Trait for platform-specific port scanning implementations.
pub trait PortScanner {
    /// Scan all ports and return entries.
    fn scan(&self) -> Result<Vec<PortEntry>, ScanError>;
}

/// Errors that can occur during port scanning.
#[derive(Debug)]
pub enum ScanError {
    PermissionDenied(String),
    ParseError(String),
    IoError(std::io::Error),
    PlatformError(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            ScanError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            ScanError::IoError(err) => write!(f, "I/O error: {}", err),
            ScanError::PlatformError(msg) => write!(f, "Platform error: {}", msg),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        ScanError::IoError(err)
    }
}

/// Create a platform-appropriate scanner instance.
pub fn create_scanner() -> Box<dyn PortScanner> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxScanner)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacosScanner)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsScanner)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        compile_error!("portpeek does not support this platform yet");
    }
}

/// Resolve PID to process name (cross-platform).
pub fn resolve_process_name(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim().to_string())
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .ok()
            .and_then(|o| {
                let name = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if name.is_empty() {
                    None
                } else {
                    Some(name)
                }
            })
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/NH", "/FO", "CSV"])
            .output()
            .ok()
            .and_then(|o| {
                let line = String::from_utf8_lossy(&o.stdout);
                line.split(',')
                    .next()
                    .map(|s| s.trim_matches('"').trim().to_string())
                    .filter(|s| !s.is_empty() && s != "INFO:")
            })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = pid;
        None
    }
}
