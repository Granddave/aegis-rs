use color_eyre::Result;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io;

use app::App;
use event::{Event, EventHandler};
use handler::handle_key_events;
use terminal::Tui;

use crate::Config;

use self::app::AppState;

/// Application.
pub mod app;

/// Terminal events handler.
pub mod event;

/// Widget renderer.
pub mod ui;

/// Terminal user interface.
pub mod terminal;

/// Event handler.
pub mod handler;

pub async fn run(config: &Config) -> Result<()> {
    let mut app = App::new(&config);

    let backend = CrosstermBackend::new(io::stderr());
    let terminal = Terminal::new(backend)?;
    let events = EventHandler::new();
    let mut tui = Tui::new(terminal, events);
    tui.init()?;

    while app.state != AppState::Quit {
        tui.draw(&mut app)?;
        match tui.events.next().await? {
            Event::Tick(duration) => app.tick(duration)?,
            Event::Key(key_event) => handle_key_events(key_event, &mut app)?,
            Event::Mouse(_) => {}
            Event::Resize(_, _) => {}
        }
    }

    tui.exit()?;
    Ok(())
}
