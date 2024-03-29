use color_eyre::eyre::Result;
use std::{fs, process::exit, time::Duration};

use aegis_vault_utils::{
    otp::{calculate_remaining_time, generate_otp, Entry, EntryInfo},
    vault::parse_vault,
};

use crate::Config;

#[derive(Debug, PartialEq)]
pub enum AppState {
    Locked,
    Selection,
    Display(Entry),
    Quit,
}

#[derive(Debug)]
pub struct App {
    pub state: AppState,
    pub config: Config,
    pub db: Option<Vec<Entry>>,

    cached_code: Option<String>,
    last_remaining_time: i32,
    alive: Duration,
}

impl App {
    pub fn new(config: &Config) -> Self {
        Self {
            state: AppState::Locked,
            config: config.clone(),
            db: None,

            cached_code: None,
            last_remaining_time: 0,
            alive: Duration::from_secs(0),
        }
    }

    fn get_entries(&self) -> Vec<Entry> {
        let file_contents = match fs::read_to_string(&self.config.vault_file) {
            Ok(contents) => contents,
            Err(e) => {
                eprintln!("Failed to read vault file: {}", e);
                exit(1); // TODO: exit application with error
            }
        };
        let entries = match parse_vault(&file_contents, &self.config.password_input) {
            Ok(db) => db
                .entries
                .into_iter()
                // Only TOTP entries are supported at the moment remove this filter later
                .filter(|e| matches!(e.info, EntryInfo::Totp(_)))
                // .filter(|e| args.entry_filter.matches(e))
                .collect::<Vec<Entry>>(),
            Err(e) => {
                eprintln!("Failed to open vault: {}", e);
                exit(1);
            }
        };

        entries
    }

    pub fn tick(&mut self, duration: Duration) -> Result<()> {
        self.alive += duration;
        match &self.state {
            AppState::Display(entry) => {
                let remaining_time = calculate_remaining_time(&entry.info)?;
                if self.last_remaining_time < remaining_time {
                    self.cached_code = Some(generate_otp(&entry.info)?);
                    // if let Some(clipboard) = clipboard.as_mut() {
                    //     clipboard.set_text(otp_code.clone())?;
                    // }
                }
                self.last_remaining_time = remaining_time;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn quit(&mut self) {
        self.state = AppState::Quit;
    }

    pub fn get_code(&self, entry: &Entry) -> Result<String> {
        // TODO: Throw error if not in Display state
        let otp_code = match &self.cached_code {
            Some(code) => code.clone(),
            None => generate_otp(&entry.info)?,
        };
        let remaining_time = calculate_remaining_time(&entry.info)?;
        // TODO: Move to UI
        let line = format!("{} ({}s left)", otp_code, remaining_time);
        Ok(line)
    }
}
