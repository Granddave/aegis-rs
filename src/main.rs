extern crate serde_json;

use aegis_rs::{
    parse_aegis_backup_file,
    totp::{calculate_remaining_time, generate_totp, EntryTypes},
    Entry,
};
use color_eyre::eyre::{eyre, Result};
use dialoguer::{theme::ColorfulTheme, FuzzySelect};
use std::env;

fn set_sigint_hook() {
    ctrlc::set_handler(move || {
        // Reset terminal after
        print!("{esc}c", esc = 27 as char);
    })
    .expect("Failed to set SIGINT handler");
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let args: Vec<String> = env::args().collect();
    let filepath = match args.get(1) {
        Some(fp) => fp,
        None => return Err(eyre!("No filepath argument")),
    };
    let entries: Vec<Entry> = parse_aegis_backup_file(filepath)?;
    let totp_entries: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.r#type == EntryTypes::Totp)
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
            println!(
                "{}, ({}s left)",
                generate_totp(totp_info)?,
                calculate_remaining_time(totp_info.period)
            );
        }
        None => {
            println!("No selection");
        }
    }

    Ok(())
}
