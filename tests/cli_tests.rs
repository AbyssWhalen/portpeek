use std::process::Command;

/// Get the path to the compiled binary (debug or release).
fn portpeek_bin() -> String {
    let (debug, release) = if cfg!(windows) {
        ("target/debug/portpeek.exe", "target/release/portpeek.exe")
    } else {
        ("target/debug/portpeek", "target/release/portpeek")
    };

    if std::path::Path::new(release).exists() {
        release.to_string()
    } else {
        debug.to_string()
    }
}

#[test]
fn test_help_flag() {
    let output = Command::new(portpeek_bin())
        .arg("--help")
        .output()
        .expect("Failed to run portpeek --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("portpeek"));
    assert!(stdout.contains("Fast, colorful port inspector"));
}

#[test]
fn test_version_flag() {
    let output = Command::new(portpeek_bin())
        .arg("--version")
        .output()
        .expect("Failed to run portpeek --version");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("portpeek"));
}

#[test]
fn test_json_output() {
    let output = Command::new(portpeek_bin())
        .args(["--json", "--no-color"])
        .output()
        .expect("Failed to run portpeek --json");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should be valid JSON (even if empty array)
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
    assert!(parsed.is_ok(), "Output should be valid JSON: {}", stdout);
}

#[test]
fn test_no_color_flag() {
    let output = Command::new(portpeek_bin())
        .args(["--no-color"])
        .output()
        .expect("Failed to run portpeek --no-color");

    assert!(output.status.success());
}

#[test]
fn test_specific_port() {
    // Querying a port that likely isn't in use should succeed (empty result)
    let output = Command::new(portpeek_bin())
        .args(["--no-color", "59999"])
        .output()
        .expect("Failed to run portpeek with port filter");

    assert!(output.status.success());
}

#[test]
fn test_kill_nonexistent_port() {
    // Killing a port that's not in use should print an error message but not crash
    let output = Command::new(portpeek_bin())
        .args(["kill", "59999", "--force"])
        .output()
        .expect("Failed to run portpeek kill");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Either stdout or stderr should mention no process found
    assert!(
        stdout.contains("No process found") || stderr.contains("No process found") || output.status.success(),
        "Should handle nonexistent port gracefully"
    );
}

#[test]
fn test_range_format() {
    // Invalid range format should produce a warning
    let output = Command::new(portpeek_bin())
        .args(["--no-color", "--range", "invalid"])
        .output()
        .expect("Failed to run portpeek --range");

    // Should still succeed (just ignore bad range with a warning)
    assert!(output.status.success());
}
