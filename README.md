# portpeek

> Fast, colorful port inspector. Know who's using your ports in milliseconds.

[![CI](https://github.com/AbyssWhalen/portpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/AbyssWhalen/portpeek/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/portpeek)](https://crates.io/crates/portpeek)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A modern replacement for `lsof -i` / `netstat` / `ss` that gives you a clean, colored overview of which ports are in use on your machine -- and which processes own them.

```
 PORT   PROTO   STATE      PID   PROCESS           BIND
 3000   TCP     LISTEN     4218  node               127.0.0.1
 5432   TCP     LISTEN     1024  postgres           0.0.0.0 ⚠
 8080   TCP     LISTEN     7821  java (spring-boot) 127.0.0.1
 8443   TCP     LISTEN     7821  java (spring-boot) 127.0.0.1
 53     UDP     LISTEN     512   dnsmasq            127.0.0.1

 ⚠ = bound to all interfaces (internet-accessible)

 5 ports in use · 1 warning
```

## Quick Start

```bash
# Install
cargo install portpeek

# See what's listening on your machine
portpeek

# Check a specific port
portpeek 8080

# Kill whatever is using port 8080
portpeek kill 8080
```

## Why portpeek?

| Feature | portpeek | lsof -i | netstat | ss |
|---|---|---|---|---|
| Clean table output | Yes | No | No | No |
| Colored terminal | Yes | No | No | No |
| Public bind warnings | Yes | No | No | No |
| Cross-platform | Yes | macOS/Linux | Varies | Linux only |
| Kill process by port | Yes | No | No | No |
| JSON output | Yes | No | No | No |
| Watch mode | Yes | No | No | No |
| Well-known port names | Yes | No | No | No |

> **When NOT to use portpeek:** `lsof` and `ss` support Unix domain sockets, detailed TCP filtering, and more advanced use cases. portpeek focuses on the common "who's using this port?" workflow.

## Installation

### From crates.io (recommended)

```bash
cargo install portpeek
```

Requires Rust 1.74 or later.

### From pre-built binaries

Download the binary for your platform from the [releases page](https://github.com/AbyssWhalen/portpeek/releases). Available for Linux (x86_64), macOS (x86_64 + Apple Silicon), and Windows (x86_64).

### From source

```bash
git clone https://github.com/AbyssWhalen/portpeek.git
cd portpeek
cargo install --path .
```

### Verify installation

```bash
portpeek --version
```

## Usage

### List all listening ports

```bash
portpeek
```

By default, portpeek shows only ports in the `LISTEN` state. Use `--all` to include established connections, time-wait sockets, etc.

### Check a specific port

```bash
portpeek 8080
```

### Filter by process name

```bash
portpeek --process node
```

The filter is case-insensitive and matches substrings, so `node` will also match `Node.js`, `nodemon`, etc. Short flag: `-p`.

### Scan a port range

```bash
portpeek --range 3000-4000
```

Short flag: `-r`.

### Show all connection states

```bash
portpeek --all
```

By default, only `LISTEN` ports are shown. With `--all` you'll also see `ESTABLISHED`, `TIME_WAIT`, `CLOSE_WAIT`, `SYN_SENT`, `FIN_WAIT1`, `FIN_WAIT2`, `CLOSING`, and `LAST_ACK`. Short flag: `-a`.

### JSON output (for scripts and CI)

```bash
portpeek --json
```

```json
[
  {
    "port": 8080,
    "protocol": "TCP",
    "state": "LISTEN",
    "pid": 7821,
    "process": "java",
    "bind_address": "127.0.0.1",
    "is_public": false
  }
]
```

The `is_public` field is `true` when the process is bound to `0.0.0.0` or `::` (all interfaces), meaning the port is accessible from the network.

### Disable colored output

```bash
portpeek --no-color
```

Useful when piping to `grep`, `less`, or redirecting to a file. Also recommended for CI environments.

### Watch mode (continuous monitoring)

```bash
portpeek --watch           # refresh every 2 seconds (default)
portpeek --watch -w 5      # refresh every 5 seconds
```

Press `q`, `Esc`, or `Ctrl+C` to exit watch mode. All filters (`--process`, `--all`, `--range`, specific port) work in watch mode too:

```bash
portpeek --watch --process node --range 3000-4000
```

Short flag: `-W` for `--watch`, `-w` for interval seconds.

### Kill process on a port

```bash
portpeek kill 8080              # prompts for confirmation
portpeek kill 8080 --force      # skip confirmation (short: -f)
```

If the port is not in use, portpeek prints a message and exits cleanly.

### Open port in browser

```bash
portpeek open 3000              # opens http://localhost:3000
```

Uses your system's default browser opener (`open` on macOS, `xdg-open` on Linux, `start` on Windows).

## Option Reference

```
USAGE:
    portpeek [OPTIONS] [PORT]
    portpeek <COMMAND>

COMMANDS:
    kill <PORT>     Kill the process occupying a specific port
    open <PORT>     Open http://localhost:<PORT> in the default browser

ARGS:
    <PORT>          Specific port number to inspect

OPTIONS:
    -a, --all               Show all connection states (not just LISTEN)
    -p, --process <NAME>    Filter by process name (case-insensitive substring match)
    -r, --range <START-END> Port range to scan (e.g. 3000-4000)
        --json              Output as JSON
        --no-color          Disable colored output
    -W, --watch             Enable watch mode (continuous monitoring)
    -w <SECONDS>            Watch mode refresh interval (default: 2)
    -h, --help              Print help
    -V, --version           Print version
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (scan completed, or no ports found for query) |
| 1 | Error (scan failed, permission denied, invalid arguments) |

portpeek exits 0 even when no ports match your filter -- this makes it safe to use in CI pipelines without special error handling.

## CI Integration

Detect port conflicts before deploying:

```yaml
# .github/workflows/deploy.yml
- name: Check port availability
  run: |
    # Fail if any port in 3000-4000 is occupied
    count=$(portpeek --json --range 3000-4000 | jq 'length')
    if [ "$count" -gt 0 ]; then
      echo "Port conflict detected!"
      portpeek --range 3000-4000
      exit 1
    fi
```

## Platform Support

| Platform | Method | Root Required |
|---|---|---|
| Linux | `/proc` filesystem parsing | No (graceful degradation) |
| macOS | `lsof` output parsing | No (graceful degradation) |
| Windows | Win32 API (`GetExtendedTcpTable`) | No |

### Running with elevated privileges

Without root/admin privileges, some process information may be hidden (PID and process name show as `-`). portpeek still shows port, protocol, state, and bind address. To see full information:

```bash
# Linux / macOS
sudo portpeek

# Windows: run from an elevated Command Prompt or PowerShell
```

## Troubleshooting

**"No process found on port X"** when using `kill`: The port is not currently in use by any process. Verify with `portpeek <port>` first.

**PID/process columns show `-`**: Your user doesn't have permission to inspect other processes. Run with `sudo` (Linux/macOS) or as Administrator (Windows).

**IPv6 ports not showing**: Ensure your system has IPv6 enabled. portpeek scans both IPv4 and IPv6 automatically.

**Watch mode leaves terminal in a weird state**: This shouldn't happen (portpeek restores terminal state even on errors), but if it does, run `reset` in your terminal.

## Development

```bash
git clone https://github.com/AbyssWhalen/portpeek.git
cd portpeek

cargo build              # debug build
cargo test               # run all tests
cargo clippy             # lint
cargo fmt -- --check     # format check
cargo run -- --process node  # run with arguments
cargo build --release    # optimized build
```

Minimum supported Rust version: **1.74**

## Contributing

Contributions are welcome! Here's how:

1. Fork the repo and create a branch
2. Make your changes (add tests if applicable)
3. Run `cargo test && cargo clippy && cargo fmt -- --check`
4. Open a pull request

For bug reports and feature requests, [open an issue](https://github.com/AbyssWhalen/portpeek/issues).

## Roadmap

- [x] Watch mode (continuous monitoring)
- [x] Port range scanning
- [x] `open` subcommand (open in browser)
- [ ] Process tree visualization
- [ ] Known port database (extended)
- [ ] Homebrew/apt package distribution
- [ ] Shell completions (bash/zsh/fish)

## License

[MIT](LICENSE) -- Copyright (c) 2026 portpeek contributors
