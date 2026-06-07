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

/// Resolve PID to process name using sysinfo crate (cross-platform fallback).
pub fn resolve_process_name(pid: u32) -> Option<String> {
    use sysinfo::{Pid, System};

    let mut sys = System::new();
    sys.refresh_processes();

    let pid = Pid::from(pid);
    sys.process(pid).map(|p| p.name().to_string())
}
