use aegis_rs::password_input::PasswordInput;

use clap::{crate_version, Args, Parser};
use color_eyre::eyre::Result;
use console::{Style, Term};
use dialoguer::{theme::ColorfulTheme, FuzzySelect};
use std::{env, fs, path::PathBuf, process::exit, time::Duration};

use aegis_vault_utils::{
    otp::{calculate_remaining_time, generate_otp, Entry, EntryInfo},
    vault::parse_vault,
};

//
// fn set_sigint_hook() {
//     ctrlc::set_handler(move || {
//         Term::stdout().show_cursor().expect("Showing cursor");
//         exit(0);
//     })
//     .expect("Setting SIGINT handler");
// }
//
// fn print_otp_every_second(entry_info: &EntryInfo) -> Result<()> {
//     let term = Term::stdout();
//     term.hide_cursor()?;
//
//     let mut clipboard = arboard::Clipboard::new().ok();
//     let mut otp_code = String::new();
//     let mut last_remaining_time = 0;
//
//     loop {
//         let remaining_time = calculate_remaining_time(entry_info)?;
//         if last_remaining_time < remaining_time {
//             otp_code = generate_otp(entry_info)?;
//             if let Some(clipboard) = clipboard.as_mut() {
//                 clipboard.set_text(otp_code.clone())?;
//             }
//         }
//
//         let style = match remaining_time {
//             0..=5 => Style::new().red(),
//             6..=15 => Style::new().yellow(),
//             _ => Style::new().green(),
//         };
//         let line = style
//             .bold()
//             .apply_to(format!("{} ({}s left)", otp_code, remaining_time));
//         term.write_line(line.to_string().as_str())?;
//         std::thread::sleep(Duration::from_secs(1));
//         term.clear_last_lines(1)?;
//         last_remaining_time = remaining_time;
//     }
// }
//
//
// fn fuzzy_select(entries: &[Entry]) -> Result<()> {
//     let items: Vec<String> = entries
//         .iter()
//         .map(|entry| format!("{} ({})", entry.issuer.trim(), entry.name.trim()))
//         .collect();
//     set_sigint_hook();
//     let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
//         .items(&items)
//         .default(0)
//         .interact_opt()?;
//     match selection {
//         Some(index) => {
//             let entry_info = &entries.get(index).unwrap().info;
//             print_otp_every_second(entry_info)?;
//         }
//         None => {
//             println!("No selection");
//         }
//     }
//     Ok(())
// }
//
// fn cli() -> Result<()> {
//     let args = Cli::parse();
//
//     let file_contents = match fs::read_to_string(&args.vault_file) {
//         Ok(contents) => contents,
//         Err(e) => {
//             eprintln!("Failed to read vault file: {}", e);
//             exit(1);
//         }
//     };
//     let entries = match parse_vault(&file_contents, args.password_input) {
//         Ok(db) => db
//             .entries
//             .into_iter()
//             // Only TOTP entries are supported at the moment remove this filter later
//             .filter(|e| matches!(e.info, EntryInfo::Totp(_)))
//             .filter(|e| args.entry_filter.matches(e))
//             .collect::<Vec<Entry>>(),
//         Err(e) => {
//             eprintln!("Failed to open vault: {}", e);
//             exit(1);
//         }
//     };
//
//     if entries.is_empty() {
//         println!("Found no matching entries based on filters and supported vault entries");
//         return Ok(());
//     }
//
//     if args.json {
//         entries_to_json(&entries)?;
//     } else {
//         fuzzy_select(&entries)?;
//     }
//
//     Ok(())
// }
//
#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let config = aegis_rs::Config::parse();
    aegis_rs::tui::run(&config).await
}
