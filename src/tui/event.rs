use std::time::Duration;

use color_eyre::Result;
use crossterm::event::{Event as CrosstermEvent, KeyEvent, MouseEvent};
use futures::{FutureExt, StreamExt};
use tokio::sync::mpsc;

const TICK_RATE_MS: u64 = 250;

/// Terminal events.
#[derive(Clone, Copy, Debug)]
pub enum Event {
    /// Terminal tick with delta time.
    Tick(Duration),
    /// Key press.
    Key(KeyEvent),
    /// Mouse click/scroll.
    Mouse(MouseEvent),
    /// Terminal resize.
    Resize(u16, u16),
}

/// Terminal event handler.
#[allow(dead_code)]
#[derive(Debug)]
pub struct EventHandler {
    sender: mpsc::UnboundedSender<Event>,
    receiver: mpsc::UnboundedReceiver<Event>,
    handler_thread: tokio::task::JoinHandle<()>,
}

impl EventHandler {
    pub fn new() -> Self {
        let tick_rate = Duration::from_millis(TICK_RATE_MS);

        let (sender, receiver) = mpsc::unbounded_channel();
        let _sender = sender.clone();

        let handler_thread = tokio::spawn(async move {
            let mut event_reader = crossterm::event::EventStream::new();
            let mut tick = tokio::time::interval(tick_rate);
            loop {
                let tick_delay = tick.tick();
                let crossterm_event = event_reader.next().fuse();
                tokio::select! {
                    _ = _sender.closed()  => {
                        break;
                    }
                    _ = tick_delay => {
                        _sender.send(Event::Tick(tick_rate)).unwrap();
                    }
                    Some(Ok(evt)) = crossterm_event => {
                        match evt {
                            CrosstermEvent::Key(key) => {
                                if key.kind == crossterm::event::KeyEventKind::Press {
                                    _sender.send(Event::Key(key)).unwrap();
                                }
                            },
                            CrosstermEvent::Mouse(mouse) => {
                                _sender.send(Event::Mouse(mouse)).unwrap();
                            },
                            CrosstermEvent::Resize(x, y) => {
                                _sender.send(Event::Resize(x, y)).unwrap();
                            },
                            CrosstermEvent::FocusLost => {},
                            CrosstermEvent::FocusGained => {},
                            CrosstermEvent::Paste(_) => {},
                        }
                    }
                };
            }
        });
        Self {
            sender,
            receiver,
            handler_thread,
        }
    }

    /// Receive the next event from the handler thread.
    ///
    /// This function will always block the current thread if
    /// there is no data available and it's possible for more data to be sent.
    pub async fn next(&mut self) -> Result<Event> {
        self.receiver.recv().await.ok_or(color_eyre::eyre::eyre!(
            "Event handler thread has been terminated"
        ))
    }
}
