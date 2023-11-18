extern crate serde_json;

use color_eyre::eyre::{eyre, Result};
use console::{Style, Term};
use dialoguer::{theme::ColorfulTheme, FuzzySelect, Password};
use std::{
    env,
    fs::{self, File},
    io::Read,
    path::PathBuf,
    process::exit,
    time::Duration,
};

use aegis_rs::{
    totp::{calculate_remaining_time, generate_totp, EntryInfo},
    vault::{Entry, Vault},
};

fn set_sigint_hook() {
    ctrlc::set_handler(move || {
        Term::stdout().show_cursor().expect("Shwoing cursor");
        exit(0);
    })
    .expect("Setting SIGINT handler");
}

fn print_totp_every_second(entry_info: &EntryInfo) -> Result<()> {
    let term = Term::stdout();
    term.hide_cursor()?;

    let mut clipboard = arboard::Clipboard::new()?;
    let mut totp_code = String::new();
    let mut last_remaining_time = 0;

    loop {
        let remaining_time = calculate_remaining_time(entry_info)?;
        if last_remaining_time < remaining_time {
            totp_code = generate_totp(entry_info)?;
            clipboard.set_text(totp_code.clone())?;
        }

        let style = match remaining_time {
            0..=5 => Style::new().red(),
            6..=15 => Style::new().yellow(),
            _ => Style::new().green(),
        };
        let line = style
            .bold()
            .apply_to(format!("{} ({}s left)", totp_code, remaining_time));
        term.write_line(line.to_string().as_str())?;
        std::thread::sleep(Duration::from_secs(1));
        term.clear_last_lines(1)?;
        last_remaining_time = remaining_time;
    }
}

/// Get password from user
fn get_password() -> Result<String> {
    // TODO: Refactor out password filepath
    let home = env::var("HOME").expect("Failed to expand $HOME");
    let password_filepath = PathBuf::from(home).join(".config/aegis-pass.txt");

    if fs::metadata(&password_filepath).is_ok() {
        println!("Found password file");
        let password = fs::read_to_string(&password_filepath)?;
        return Ok(password.trim().to_string());
    } else {
        return Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Insert Aegis Password")
            .interact()
            .map_err(|e| eyre!("Failed to get password: {}", e));
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let args: Vec<String> = env::args().collect();
    let filepath = match args.get(1) {
        Some(fp) => fp,
        None => return Err(eyre!("No filepath argument")),
    };
    let mut file = File::open(filepath)?;
    let mut file_contents = String::new();
    file.read_to_string(&mut file_contents)?;
    let entries: Vec<Entry> = Vault::parse(&file_contents, get_password)?;
    let totp_entries: Vec<&Entry> = entries
        .iter()
        .filter(|e| matches!(e.info, EntryInfo::Totp(_)))
        .collect();

    if totp_entries.is_empty() {
        println!("Found no entries of the supported entry types (TOTP)");
        return Ok(());
    }

    let items: Vec<String> = totp_entries
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
            let totp_info = &totp_entries.get(index).unwrap().info;
            print_totp_every_second(totp_info)?;
        }
        None => {
            println!("No selection");
        }
    }

    Ok(())
}
