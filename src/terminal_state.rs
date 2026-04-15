use std::io;

/// A snapshot of the terminal's input flags that can be restored later.
///
/// On Unix this captures the full `termios` struct (via `tcgetattr`).
/// On Windows we stub this out since the initial issue was on Linux.
#[derive(Clone, Copy)]
pub struct TerminalState {
    inner: PlatformState,
}

impl TerminalState {
    /// Snapshot the current terminal input flags.
    pub fn save() -> io::Result<Self> {
        Ok(Self {
            inner: PlatformState::save()?,
        })
    }

    /// Restore the previously saved terminal input flags.
    pub fn restore(&self) -> io::Result<()> {
        self.inner.restore()
    }
}

// Unix (Linux, macOS, etc.)

#[cfg(unix)]
#[derive(Clone, Copy)]
struct PlatformState {
    termios: libc::termios,
}

#[cfg(unix)]
impl PlatformState {
    fn save() -> io::Result<Self> {
        let mut termios = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut termios) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { termios })
    }

    fn restore(&self) -> io::Result<()> {
        let ret = unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.termios) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

// Windows (stub)

#[cfg(not(unix))]
#[derive(Clone, Copy)]
struct PlatformState;

#[cfg(not(unix))]
impl PlatformState {
    fn save() -> io::Result<Self> {
        Ok(Self)
    }

    fn restore(&self) -> io::Result<()> {
        Ok(())
    }
}
