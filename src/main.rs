use clap::Parser;
use color_eyre::eyre::{eyre, Result};
use console::{Style, Term};
use dialoguer::{theme::ColorfulTheme, FuzzySelect, Password};
use std::{
    env,
    fs::{self, File},
    io::Read,
    process::exit,
    time::Duration,
};

use aegis_rs::{
    otp::{calculate_remaining_time, generate_otp, Entry, EntryInfo},
    vault::{parse_vault, PasswordGetter},
};

#[derive(Parser)]
#[clap(name = "aegis-rs", about = "OTP generator for Aegis vaults")]
struct Args {
    #[clap(help = "Path to the vault file")]
    vault: String,
    #[clap(short, long, help = "Path to the password file")]
    password_file: Option<String>,
}

fn set_sigint_hook() {
    ctrlc::set_handler(move || {
        Term::stdout().show_cursor().expect("Shwoing cursor");
        exit(0);
    })
    .expect("Setting SIGINT handler");
}

fn print_otp_every_second(entry_info: &EntryInfo) -> Result<()> {
    let term = Term::stdout();
    term.hide_cursor()?;

    let mut clipboard = arboard::Clipboard::new()?;
    let mut otp_code = String::new();
    let mut last_remaining_time = 0;

    loop {
        let remaining_time = calculate_remaining_time(entry_info)?;
        if last_remaining_time < remaining_time {
            otp_code = generate_otp(entry_info)?;
            clipboard.set_text(otp_code.clone())?;
        }

        let style = match remaining_time {
            0..=5 => Style::new().red(),
            6..=15 => Style::new().yellow(),
            _ => Style::new().green(),
        };
        let line = style
            .bold()
            .apply_to(format!("{} ({}s left)", otp_code, remaining_time));
        term.write_line(line.to_string().as_str())?;
        std::thread::sleep(Duration::from_secs(1));
        term.clear_last_lines(1)?;
        last_remaining_time = remaining_time;
    }
}

struct PasswordInput {
    password_file: Option<String>,
}

impl PasswordInput {
    fn read_password_from_file(&self, password_file: &str) -> Result<String> {
        let password = fs::read_to_string(password_file)?;
        Ok(password.trim().to_string())
    }
}

impl PasswordGetter for PasswordInput {
    fn get_password(&self) -> Result<String> {
        if let Some(password_filepath) = &self.password_file {
            return self.read_password_from_file(password_filepath);
        } else if let Ok(password_file) = env::var("AEGIS_PASSWORD_FILE") {
            return self.read_password_from_file(&password_file);
        } else if let Ok(password) = env::var("AEGIS_PASSWORD") {
            return Ok(password);
        } else {
            return Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Insert Aegis Password")
                .interact()
                .map_err(|e| eyre!("Failed to get password: {}", e));
        }
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Args::parse();
    let password_input = PasswordInput {
        password_file: args.password_file,
    };

    let mut file = File::open(args.vault)?;
    let mut file_contents = String::new();
    file.read_to_string(&mut file_contents)?;
    let entries: Vec<Entry> = parse_vault(&file_contents, password_input)?;
    let entries: Vec<&Entry> = entries
        .iter()
        .filter(|e| matches!(e.info, EntryInfo::Totp(_)))
        .collect();

    if entries.is_empty() {
        println!("Found no entries of the supported entry types (TOTP)");
        return Ok(());
    }

    let items: Vec<String> = entries
        .iter()
        .map(|entry| format!("{} ({})", entry.issuer.trim(), entry.name.trim()))
        .collect();
    set_sigint_hook();
    let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
        .items(&items)
        .default(0)
        .interact_opt()?;
    match selection {
        Some(index) => {
            let entry_info = &entries.get(index).unwrap().info;
            print_otp_every_second(entry_info)?;
        }
        None => {
            println!("No selection");
        }
    }

    Ok(())
}
