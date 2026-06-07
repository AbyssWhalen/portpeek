use crate::model::*;
use crate::scanner::{PortScanner, ScanError};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

pub struct LinuxScanner;

impl PortScanner for LinuxScanner {
    fn scan(&self) -> Result<Vec<PortEntry>, ScanError> {
        let mut entries = Vec::new();

        // Build inode → PID mapping from /proc/[pid]/fd
        let inode_to_pid = build_inode_pid_map()?;

        // Parse TCP connections (IPv4)
        parse_proc_net_file("/proc/net/tcp", Protocol::TCP, false, &inode_to_pid, &mut entries)?;

        // Parse TCP connections (IPv6)
        if Path::new("/proc/net/tcp6").exists() {
            parse_proc_net_file("/proc/net/tcp6", Protocol::TCP, true, &inode_to_pid, &mut entries)?;
        }

        // Parse UDP connections (IPv4)
        if Path::new("/proc/net/udp").exists() {
            parse_proc_net_file("/proc/net/udp", Protocol::UDP, false, &inode_to_pid, &mut entries)?;
        }

        // Parse UDP connections (IPv6)
        if Path::new("/proc/net/udp6").exists() {
            parse_proc_net_file("/proc/net/udp6", Protocol::UDP, true, &inode_to_pid, &mut entries)?;
        }

        // Resolve process names for entries with PIDs
        for entry in &mut entries {
            if let Some(pid) = entry.pid {
                entry.process_name = super::resolve_process_name(pid);
            }
        }

        entries.sort_by_key(|e| e.port);
        Ok(entries)
    }
}

/// Build a mapping from socket inode number to PID by scanning /proc/[pid]/fd/
fn build_inode_pid_map() -> Result<HashMap<u64, u32>, ScanError> {
    let mut map = HashMap::new();
    let proc_dir = fs::read_dir("/proc").map_err(ScanError::IoError)?;

    for proc_entry in proc_dir {
        let proc_entry = match proc_entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let name = proc_entry.file_name();
        let name_str = name.to_string_lossy();

        // Only look at numeric directories (PIDs)
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{}/fd", pid);
        let fd_entries = match fs::read_dir(&fd_dir) {
            Ok(e) => e,
            Err(_) => continue, // Permission denied for this process, skip
        };

        for fd_entry in fd_entries {
            let fd_entry = match fd_entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let link = match fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };

            let link_str = link.to_string_lossy();
            // Socket links look like: "socket:[12345]"
            if link_str.starts_with("socket:[") {
                let inode_str = &link_str[8..link_str.len() - 1];
                if let Ok(inode) = inode_str.parse::<u64>() {
                    map.insert(inode, pid);
                }
            }
        }
    }

    Ok(map)
}

/// Parse a /proc/net/{tcp,tcp6,udp,udp6} file and append entries to the result vector.
fn parse_proc_net_file(
    path: &str,
    protocol: Protocol,
    is_ipv6: bool,
    inode_to_pid: &HashMap<u64, u32>,
    entries: &mut Vec<PortEntry>,
) -> Result<(), ScanError> {
    let content = fs::read_to_string(path).map_err(ScanError::IoError)?;

    for line in content.lines().skip(1) {
        // Skip the header line
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        // Fields:
        // 0: sl (index)
        // 1: local_address (hex_addr:hex_port)
        // 2: rem_address
        // 3: st (state hex)
        // 4: tx_queue:rx_queue
        // 5: tr:when
        // 6: retrnsmt
        // 7: uid
        // 8: timeout
        // 9: inode
        let (bind_addr, port) = if is_ipv6 {
            match parse_linux_addr_port_v6(fields[1]) {
                Some(v) => v,
                None => continue,
            }
        } else {
            match parse_linux_addr_port(fields[1]) {
                Some(v) => v,
                None => continue,
            }
        };

        let state = if protocol == Protocol::TCP {
            ConnectionState::from_linux_hex(fields[3])
        } else {
            // UDP doesn't have connection states; treat as "Listen" if there's a local address
            ConnectionState::Listen
        };

        let inode: u64 = fields[9].parse().unwrap_or(0);
        let pid = inode_to_pid.get(&inode).copied();

        let is_public = is_public_bind(&bind_addr);

        entries.push(PortEntry {
            port,
            protocol,
            state,
            pid,
            process_name: None, // resolved later
            bind_address: bind_addr,
            is_public,
        });
    }

    Ok(())
}
