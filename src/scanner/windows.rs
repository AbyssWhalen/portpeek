use crate::model::*;
use crate::scanner::{PortScanner, ScanError};
use std::net::IpAddr;

pub struct WindowsScanner;

impl PortScanner for WindowsScanner {
    fn scan(&self) -> Result<Vec<PortEntry>, ScanError> {
        let mut entries = Vec::new();

        // TCP IPv4
        scan_tcp_v4(&mut entries)?;

        // TCP IPv6
        if let Err(e) = scan_tcp_v6(&mut entries) {
            eprintln!("Warning: could not scan IPv6 TCP: {}", e);
        }

        // UDP IPv4
        scan_udp_v4(&mut entries)?;

        // UDP IPv6
        if let Err(e) = scan_udp_v6(&mut entries) {
            eprintln!("Warning: could not scan IPv6 UDP: {}", e);
        }

        // Resolve process names
        for entry in &mut entries {
            if let Some(pid) = entry.pid {
                entry.process_name = super::resolve_process_name(pid);
            }
        }

        entries.sort_by_key(|e| e.port);
        entries.dedup_by(|a, b| {
            a.port == b.port && a.protocol == b.protocol && a.bind_address == b.bind_address
        });
        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// TCP IPv4
// ---------------------------------------------------------------------------

fn scan_tcp_v4(entries: &mut Vec<PortEntry>) -> Result<(), ScanError> {
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let buffer = call_get_extended_table(|buf, size| unsafe {
        WIN32_ERROR(GetExtendedTcpTable(
            Some(buf.cast()),
            size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ))
    })?;

    let table_ptr = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
    let rows_ptr = unsafe { (*table_ptr).table.as_ptr() };
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, num_entries) };

    for row in rows {
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let ip_bytes = row.dwLocalAddr.to_ne_bytes();
        let bind_addr = IpAddr::V4(std::net::Ipv4Addr::new(
            ip_bytes[0],
            ip_bytes[1],
            ip_bytes[2],
            ip_bytes[3],
        ));
        let state = ConnectionState::from_windows_state(row.dwState);

        entries.push(PortEntry {
            port,
            protocol: Protocol::TCP,
            state,
            pid: Some(row.dwOwningPid),
            process_name: None,
            bind_address: bind_addr,
            is_public: is_public_bind(&bind_addr),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// TCP IPv6
// ---------------------------------------------------------------------------

fn scan_tcp_v6(entries: &mut Vec<PortEntry>) -> Result<(), ScanError> {
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET6;

    let buffer = call_get_extended_table(|buf, size| unsafe {
        WIN32_ERROR(GetExtendedTcpTable(
            Some(buf.cast()),
            size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ))
    })?;

    let table_ptr = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
    let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
    let rows_ptr = unsafe { (*table_ptr).table.as_ptr() };
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, num_entries) };

    for row in rows {
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let bind_addr = IpAddr::V6(std::net::Ipv6Addr::from(row.ucLocalAddr));
        let state = ConnectionState::from_windows_state(row.dwState);

        entries.push(PortEntry {
            port,
            protocol: Protocol::TCP,
            state,
            pid: Some(row.dwOwningPid),
            process_name: None,
            bind_address: bind_addr,
            is_public: is_public_bind(&bind_addr),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// UDP IPv4
// ---------------------------------------------------------------------------

fn scan_udp_v4(entries: &mut Vec<PortEntry>) -> Result<(), ScanError> {
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let buffer = call_get_extended_table(|buf, size| unsafe {
        WIN32_ERROR(GetExtendedUdpTable(
            Some(buf.cast()),
            size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ))
    })?;

    let table_ptr = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
    let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
    let rows_ptr = unsafe { (*table_ptr).table.as_ptr() };
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, num_entries) };

    for row in rows {
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let ip_bytes = row.dwLocalAddr.to_ne_bytes();
        let bind_addr = IpAddr::V4(std::net::Ipv4Addr::new(
            ip_bytes[0],
            ip_bytes[1],
            ip_bytes[2],
            ip_bytes[3],
        ));

        entries.push(PortEntry {
            port,
            protocol: Protocol::UDP,
            state: ConnectionState::Listen,
            pid: Some(row.dwOwningPid),
            process_name: None,
            bind_address: bind_addr,
            is_public: is_public_bind(&bind_addr),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// UDP IPv6
// ---------------------------------------------------------------------------

fn scan_udp_v6(entries: &mut Vec<PortEntry>) -> Result<(), ScanError> {
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDP6TABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET6;

    let buffer = call_get_extended_table(|buf, size| unsafe {
        WIN32_ERROR(GetExtendedUdpTable(
            Some(buf.cast()),
            size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        ))
    })?;

    let table_ptr = buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
    let num_entries = unsafe { (*table_ptr).dwNumEntries } as usize;
    let rows_ptr = unsafe { (*table_ptr).table.as_ptr() };
    let rows = unsafe { std::slice::from_raw_parts(rows_ptr, num_entries) };

    for row in rows {
        let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        let bind_addr = IpAddr::V6(std::net::Ipv6Addr::from(row.ucLocalAddr));

        entries.push(PortEntry {
            port,
            protocol: Protocol::UDP,
            state: ConnectionState::Listen,
            pid: Some(row.dwOwningPid),
            process_name: None,
            bind_address: bind_addr,
            is_public: is_public_bind(&bind_addr),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Generic helper for GetExtended*Table pattern
// ---------------------------------------------------------------------------

use windows::Win32::Foundation::WIN32_ERROR;

/// Calls a Windows API function following the standard retry pattern:
/// 1. Call with null buffer to get required size
/// 2. Allocate buffer of that size
/// 3. Call again with buffer; retry once if buffer was too small
///
/// `api_call` should return `WIN32_ERROR`. `NO_ERROR` (0) means success.
fn call_get_extended_table<F>(api_call: F) -> Result<Vec<u8>, ScanError>
where
    F: Fn(*mut u8, &mut u32) -> WIN32_ERROR,
{
    let no_error = WIN32_ERROR(0);

    // Step 1: determine required buffer size
    let mut size: u32 = 0;
    let _ = api_call(std::ptr::null_mut(), &mut size);

    if size == 0 {
        return Err(ScanError::PlatformError(
            "Failed to determine buffer size for port table".into(),
        ));
    }

    // Step 2: allocate and call
    let mut buffer = vec![0u8; size as usize];
    let ret = api_call(buffer.as_mut_ptr(), &mut size);

    if ret == no_error {
        return Ok(buffer);
    }

    // Step 3: retry with updated size (table may have grown between calls)
    buffer.resize(size as usize, 0);
    let ret = api_call(buffer.as_mut_ptr(), &mut size);

    if ret == no_error {
        return Ok(buffer);
    }

    Err(ScanError::PlatformError(format!(
        "Port table query failed with error code {}",
        ret.0
    )))
}
