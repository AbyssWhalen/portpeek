use crate::model::{well_known_service, PortEntry};
use crate::render::Renderer;
use colored::*;
use comfy_table::{presets::UTF8_FULL, Cell, CellAlignment, Color, Table};

pub struct TableRenderer;

impl Renderer for TableRenderer {
    fn render(&self, entries: &[PortEntry], no_color: bool) -> String {
        if entries.is_empty() {
            let msg = "No ports in use.";
            return if no_color {
                msg.to_string()
            } else {
                msg.green().to_string()
            };
        }

        let mut table = Table::new();
        table.load_preset(UTF8_FULL);

        table.set_header(vec![
            Cell::new("PORT").set_alignment(CellAlignment::Right),
            Cell::new("PROTO").set_alignment(CellAlignment::Center),
            Cell::new("STATE").set_alignment(CellAlignment::Center),
            Cell::new("PID").set_alignment(CellAlignment::Right),
            Cell::new("PROCESS").set_alignment(CellAlignment::Left),
            Cell::new("BIND").set_alignment(CellAlignment::Left),
        ]);

        let mut warning_count = 0;

        for entry in entries {
            let port_str = if let Some(svc) = well_known_service(entry.port) {
                format!("{} ({})", entry.port, svc)
            } else {
                format!("{}", entry.port)
            };

            let bind_str = entry.bind_address.to_string();
            let bind_cell = if entry.is_public {
                warning_count += 1;
                if no_color {
                    Cell::new(format!("{} ⚠", bind_str))
                } else {
                    Cell::new(format!("{} ⚠", bind_str)).fg(Color::Yellow)
                }
            } else {
                if no_color {
                    Cell::new(bind_str)
                } else {
                    Cell::new(bind_str).fg(Color::Grey)
                }
            };

            let pid_str = entry
                .pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());

            let process_str = entry
                .process_name
                .as_deref()
                .unwrap_or("-");

            let state_color = match entry.state {
                crate::model::ConnectionState::Listen => Color::Green,
                crate::model::ConnectionState::Established => Color::Cyan,
                crate::model::ConnectionState::TimeWait => Color::Grey,
                _ => Color::White,
            };

            let state_cell = if no_color {
                Cell::new(entry.state.to_string())
                    .set_alignment(CellAlignment::Center)
            } else {
                Cell::new(entry.state.to_string())
                    .set_alignment(CellAlignment::Center)
                    .fg(state_color)
            };

            table.add_row(vec![
                Cell::new(port_str).set_alignment(CellAlignment::Right),
                Cell::new(entry.protocol.to_string()).set_alignment(CellAlignment::Center),
                state_cell,
                Cell::new(pid_str).set_alignment(CellAlignment::Right),
                Cell::new(process_str).set_alignment(CellAlignment::Left),
                bind_cell.set_alignment(CellAlignment::Left),
            ]);
        }

        let mut output = table.to_string();

        // Footer
        if warning_count > 0 {
            let warning_line = format!(
                "\n ⚠ = bound to all interfaces (internet-accessible)"
            );
            output.push_str(&if no_color {
                warning_line
            } else {
                warning_line.yellow().to_string()
            });
        }

        let summary = format!(
            "\n\n {} port{} in use",
            entries.len(),
            if entries.len() == 1 { "" } else { "s" }
        );
        let summary = if warning_count > 0 {
            format!("{} · {} warning{}", summary, warning_count, if warning_count == 1 { "" } else { "s" })
        } else {
            summary
        };

        output.push_str(&if no_color {
            summary
        } else {
            summary.dimmed().to_string()
        });

        output
    }
}
