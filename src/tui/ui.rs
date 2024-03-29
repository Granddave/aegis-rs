use color_eyre::eyre::{eyre, Result};
use ratatui::{
    layout::Alignment,
    style::{Color, Style},
    widgets::{Block, BorderType, Paragraph},
    Frame,
};

use crate::tui::app::{App, AppState};

/// Renders the user interface widgets.
pub fn render(app: &mut App, frame: &mut Frame) -> Result<()> {
    // This is where you add new widgets.
    // See the following resources:
    // - https://docs.rs/ratatui/latest/ratatui/widgets/index.html
    // - https://github.com/ratatui-org/ratatui/tree/master/examples

    match &app.state {
        AppState::Display(entry) => frame.render_widget(
            Paragraph::new(format!(
                "Index: {}, otp: {}",
                entry.name,
                app.get_code(entry)?
            ))
            .block(
                Block::bordered()
                    .title("Template")
                    .title_alignment(Alignment::Center)
                    .border_type(BorderType::Rounded),
            )
            .style(Style::default().fg(Color::Cyan).bg(Color::Black))
            .centered(),
            frame.size(),
        ),
        _ => {}
    }
    Ok(())
}
