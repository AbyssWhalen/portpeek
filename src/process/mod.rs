use crate::model::PortEntry;
use colored::*;
use std::io::{self, Write};

/// Kill the process occupying the specified port.
pub fn kill_on_port(
    port: u16,
    force: bool,
    entries: &[PortEntry],
    no_color: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Find entries matching the port
    let matching: Vec<&PortEntry> = entries
        .iter()
        .filter(|e| e.port == port && e.pid.is_some())
        .collect();

    if matching.is_empty() {
        if no_color {
            eprintln!("✗ No process found on port {}.", port);
        } else {
            eprintln!(
                "{} No process found on port {}.",
                "✗".red(),
                port.to_string().bold()
            );
        }
        return Ok(());
    }

    // Get unique PIDs
    let mut pids: Vec<u32> = matching.iter().filter_map(|e| e.pid).collect();
    pids.sort();
    pids.dedup();

    for pid in &pids {
        let proc_name = matching
            .iter()
            .find(|e| e.pid == Some(*pid))
            .and_then(|e| e.process_name.as_deref())
            .unwrap_or("unknown");

        if !force {
            if no_color {
                print!("Kill {} (PID {}) on port {}? [y/N] ", proc_name, pid, port);
            } else {
                print!(
                    "Kill {} (PID {}) on port {}? [y/N] ",
                    proc_name.yellow(),
                    pid.to_string().bold(),
                    port.to_string().bold()
                );
            }
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Skipped.");
                continue;
            }
        }

        kill_process(*pid)?;
        if no_color {
            println!("✓ Killed {} (PID {})", proc_name, pid);
        } else {
            println!("{} Killed {} (PID {})", "✓".green(), proc_name, pid);
        }
    }

    Ok(())
}

/// Open `http://localhost:<port>` in the default browser.
pub fn open_port(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("http://localhost:{}", port);
    println!("Opening {} ...", url.cyan());

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", &url])
            .spawn()?;
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(&url).spawn()?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(&url).spawn()?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Platform-specific process killing
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn kill_process(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()?;

    if !status.success() {
        return Err(format!("Failed to kill process {}", pid).into());
    }
    Ok(())
}

#[cfg(windows)]
fn kill_process(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    // taskkill is the Windows equivalent
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status()?;

    if !status.success() {
        return Err(format!("Failed to kill process {}", pid).into());
    }
    Ok(())
}
