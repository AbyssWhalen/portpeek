pub mod json;
pub mod table;
pub mod watch;

use crate::model::PortEntry;

/// Trait for rendering port entries in different formats.
pub trait Renderer {
    fn render(&self, entries: &[PortEntry], no_color: bool) -> String;
}
