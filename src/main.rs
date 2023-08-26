extern crate serde_json;

use color_eyre::eyre::{eyre, Result};
use dialoguer::{theme::ColorfulTheme, FuzzySelect};
use std::env;

mod aegis;

fn main() -> Result<()> {
    color_eyre::install()?;

    let args: Vec<String> = env::args().collect();
    let filepath = match args.get(1) {
        Some(fp) => fp,
        None => return Err(eyre!("No filepath argument")),
    };
    let entries: Vec<aegis::Entry> = aegis::parse_aegis_backup_file(filepath)?;
    let totp_entries: Vec<&aegis::Entry> = entries
        .iter()
        .filter(|e| e.r#type == aegis::EntryTypes::Totp)
        .collect();

    if totp_entries.is_empty() {
        println!("Found no entries of the supported entry types (TOTP)");
        return Ok(());
    }

    let items: Vec<String> = totp_entries
        .iter()
        .map(|entry| format!("{} ({})", entry.issuer.trim(), entry.name.trim()))
        .collect();
    let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
        .items(&items)
        .default(0)
        .interact_opt()?;
    match selection {
        Some(index) => {
            let totp_info = &totp_entries.get(index).unwrap().info;
            println!(
                "{}, ({}s left)",
                aegis::generate_totp(totp_info)?,
                aegis::calculate_remaining_time(totp_info.period)
            );
        }
        None => {
            println!("No selection");
        }
    }
    // TODO: Reset terminal on exit

    Ok(())
}
