use crate::model::PortEntry;
use crate::render::Renderer;

pub struct JsonRenderer;

impl Renderer for JsonRenderer {
    fn render(&self, entries: &[PortEntry], _no_color: bool) -> String {
        serde_json::to_string_pretty(entries)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e))
    }
}
