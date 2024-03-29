use std::path::PathBuf;

use clap::{crate_version, Parser};
use password_input::PasswordInput;

pub mod tui;

pub mod password_input;

pub mod json_output;

#[derive(Parser, Debug, Clone)]
#[clap(
    name = "aegis-rs",
    about = "OTP generator for Aegis vaults",
    version = crate_version!()
)]
pub struct Config {
    #[clap(help = "Path to the vault file", env = "AEGIS_VAULT_FILE")]
    vault_file: PathBuf,
    #[clap(flatten)]
    password_input: PasswordInput,
    // #[clap(flatten, help = "Filter by issuer name")]
    // entry_filter: EntryFilter,
    // #[clap(long, help = "Print to stdout in JSON")]
    // json: bool,
}

// #[derive(Args)]
// struct EntryFilter {
//     #[clap(long, help = "Filter by entry issuer")]
//     issuer: Option<String>,
//     #[clap(long, help = "Filter by entry name")]
//     name: Option<String>,
// }

// impl EntryFilter {
//     fn matches(&self, entry: &Entry) -> bool {
//         if let Some(issuer) = &self.issuer {
//             if !entry.issuer.to_lowercase().contains(&issuer.to_lowercase()) {
//                 return false;
//             }
//         }
//         if let Some(name) = &self.name {
//             if !entry.name.to_lowercase().contains(&name.to_lowercase()) {
//                 return false;
//             }
//         }
//         true
//     }
// }
