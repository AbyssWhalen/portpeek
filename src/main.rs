use clap::Parser;
use portpeek::apply_filters;
use portpeek::cli::{Cli, Command};
use portpeek::process;
use portpeek::render::json::JsonRenderer;
use portpeek::render::table::TableRenderer;
use portpeek::render::Renderer;
use portpeek::scanner::PortScanner;

fn main() {
    let cli = Cli::parse();

    // Handle subcommands first
    if let Some(command) = &cli.command {
        match command {
            Command::Kill { port, force } => {
                let scanner = portpeek::scanner::create_scanner();
                match scanner.scan() {
                    Ok(entries) => {
                        if let Err(e) = process::kill_on_port(*port, *force, &entries, cli.no_color) {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to scan ports: {}", e);
                        std::process::exit(1);
                    }
                }
                return;
            }
            Command::Open { port } => {
                if let Err(e) = process::open_port(*port) {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
                return;
            }
        }
    }

    // Create scanner
    let scanner = portpeek::scanner::create_scanner();

    // Watch mode
    if cli.watch {
        if let Err(e) = portpeek::render::watch::run_watch_mode(
            scanner.as_ref(),
            cli.interval,
            cli.no_color,
            cli.all,
            cli.process.as_deref(),
            cli.port,
            cli.range.as_deref(),
        ) {
            eprintln!("Watch mode error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // Normal scan
    let entries = match scanner.scan() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to scan ports: {}", e);
            std::process::exit(1);
        }
    };

    // Apply filters
    let filtered = apply_filters(
        entries,
        cli.all,
        cli.process.as_deref(),
        cli.port,
        cli.range.as_deref(),
    );

    // Render output
    let output = if cli.json {
        let renderer = JsonRenderer;
        renderer.render(&filtered, cli.no_color)
    } else {
        let renderer = TableRenderer;
        renderer.render(&filtered, cli.no_color)
    };

    println!("{}", output);
}
