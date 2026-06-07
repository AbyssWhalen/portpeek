use crate::model::*;
use crate::scanner::{PortScanner, ScanError};
use std::net::IpAddr;
use std::process::Command;

pub struct MacosScanner;

impl PortScanner for MacosScanner {
    fn scan(&self) -> Result<Vec<PortEntry>, ScanError> {
        // Use lsof with custom format for reliable parsing.
        // -i: internet connections
        // -P: numeric ports (no service name resolution)
        // -n: numeric addresses (no DNS resolution)
        // -F: machine-parseable output
        let output = Command::new("lsof")
            .args(["-i", "-P", "-n", "-F", "pcn"])
            .output()
            .map_err(|e| ScanError::PlatformError(format!("Failed to run lsof: {}", e)))?;

        // lsof may return non-zero if some processes are inaccessible; still parse stdout
        parse_lsof_output(&String::from_utf8_lossy(&output.stdout))
    }
}

/// Parse lsof -F pcn output.
/// Format is groups of lines per file descriptor:
///   p<pid>
///   c<command>
///   n<name>      (e.g., "127.0.0.1:8080" or "*:80" or "[::1]:8080")
///   t<type>      (e.g., "IPv4" or "IPv6")
fn parse_lsof_output(raw: &str) -> Result<Vec<PortEntry>, ScanError> {
    let mut entries = Vec::new();
    let mut current_pid: Option<u32> = None;
    let mut current_cmd: Option<String> = None;

    for line in raw.lines() {
        if line.is_empty() {
            continue;
        }

        let (prefix, value) = line.split_at(1);
        match prefix {
            "p" => {
                current_pid = value.parse().ok();
            }
            "c" => {
                current_cmd = Some(value.to_string());
            }
            "n" => {
                // Parse the network name field
                if let (Some(pid), Some(cmd)) = (current_pid, current_cmd.clone()) {
                    if let Some(entry) = parse_lsof_name(value, pid, cmd) {
                        entries.push(entry);
                    }
                }
            }
            _ => {} // ignore other fields (t, f, etc.)
        }
    }

    entries.sort_by_key(|e| e.port);
    Ok(entries)
}

/// Parse an lsof -n name field into a PortEntry.
/// Formats:
///   "127.0.0.1:8080"
///   "*:80"
///   "[::1]:8080"
///   "[::]:80"
///   "192.168.1.1:443->10.0.0.1:54321" (established - skip the remote part)
fn parse_lsof_name(name: &str, pid: u32, cmd: String) -> Option<PortEntry> {
    // Handle established connections: take only the local part
    let local_part = name.split("->").next()?;

    // Determine if TCP or UDP (lsof -F doesn't directly tell us in the 'n' field,
    // but we can infer from context. For simplicity, default to TCP for LISTEN-like entries.)
    // A more robust approach would track the 't' field, but for MVP this is sufficient.
    let protocol = Protocol::TCP;

    // Parse IPv6 bracket notation: [::1]:8080 or [::]:80
    if local_part.starts_with('[') {
        let bracket_end = local_part.find("]:")?;
        let addr_str = &local_part[1..bracket_end];
        let port_str = &local_part[bracket_end + 2..];
        let port: u16 = port_str.parse().ok()?;

        let bind_addr = if addr_str == "*" {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        } else {
            addr_str.parse().ok()?
        };

        let is_public = is_public_bind(&bind_addr);
        let state = ConnectionState::Listen; // simplified for MVP

        return Some(PortEntry {
            port,
            protocol,
            state,
            pid: Some(pid),
            process_name: Some(cmd),
            bind_address: bind_addr,
            is_public,
        });
    }

    // Parse IPv4 notation: 127.0.0.1:8080 or *:80
    let colon_pos = local_part.rfind(':')?;
    let addr_str = &local_part[..colon_pos];
    let port_str = &local_part[colon_pos + 1..];
    let port: u16 = port_str.parse().ok()?;

    let bind_addr = if addr_str == "*" {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        addr_str.parse().ok()?
    };

    let is_public = is_public_bind(&bind_addr);
    let state = ConnectionState::Listen;

    Some(PortEntry {
        port,
        protocol,
        state,
        pid: Some(pid),
        process_name: Some(cmd),
        bind_address: bind_addr,
        is_public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lsof_name_ipv4() {
        let entry = parse_lsof_name("127.0.0.1:8080", 1234, "node".to_string()).unwrap();
        assert_eq!(entry.port, 8080);
        assert_eq!(entry.bind_address, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(!entry.is_public);
    }

    #[test]
    fn test_parse_lsof_name_wildcard() {
        let entry = parse_lsof_name("*:80", 5678, "nginx".to_string()).unwrap();
        assert_eq!(entry.port, 80);
        assert!(entry.is_public);
    }

    #[test]
    fn test_parse_lsof_name_ipv6() {
        let entry = parse_lsof_name("[::1]:3000", 9999, "ruby".to_string()).unwrap();
        assert_eq!(entry.port, 3000);
        assert!(!entry.is_public);
    }

    #[test]
    fn test_parse_lsof_name_established() {
        let entry =
            parse_lsof_name("127.0.0.1:8080->10.0.0.1:54321", 1234, "node".to_string()).unwrap();
        assert_eq!(entry.port, 8080);
    }
}
