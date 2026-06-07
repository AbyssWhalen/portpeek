use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "portpeek",
    about = "Fast, colorful port inspector. Know who's using your ports in milliseconds.",
    version,
    after_help = "Examples:\n  \
        portpeek                   List all listening ports\n  \
        portpeek 8080              Check a specific port\n  \
        portpeek --process node    Filter by process name\n  \
        portpeek kill 8080         Kill the process on port 8080\n  \
        portpeek open 3000         Open http://localhost:3000 in browser"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Specific port number to inspect
    #[arg(value_name = "PORT")]
    pub port: Option<u16>,

    /// Show all connection states (not just LISTEN)
    #[arg(long, short)]
    pub all: bool,

    /// Filter by process name (substring match, case-insensitive)
    #[arg(long, short)]
    pub process: Option<String>,

    /// Port range to scan (e.g. 3000-4000)
    #[arg(long, short, value_name = "RANGE")]
    pub range: Option<String>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,

    /// Enable watch mode (continuous monitoring)
    #[arg(long, short = 'W')]
    pub watch: bool,

    /// Watch mode refresh interval in seconds
    #[arg(short = 'w', default_value = "2")]
    pub interval: u64,
}

#[derive(Subcommand)]
pub enum Command {
    /// Kill the process occupying a specific port
    Kill {
        /// Target port number
        port: u16,
        /// Force kill without confirmation
        #[arg(long, short)]
        force: bool,
    },
    /// Open http://localhost:<port> in the default browser
    Open {
        /// Target port number
        port: u16,
    },
}

impl Cli {
    /// Parse a port range string like "3000-4000" into (start, end).
    pub fn parse_range(range: &str) -> Result<(u16, u16), String> {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid range format: '{}'. Use START-END (e.g. 3000-4000)", range));
        }
        let start: u16 = parts[0]
            .parse()
            .map_err(|_| format!("Invalid start port: '{}'", parts[0]))?;
        let end: u16 = parts[1]
            .parse()
            .map_err(|_| format!("Invalid end port: '{}'", parts[1]))?;
        if start > end {
            return Err(format!("Start port {} is greater than end port {}", start, end));
        }
        Ok((start, end))
    }
}
