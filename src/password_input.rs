use aegis_vault_utils::vault::PasswordGetter;
use clap::Args;
use color_eyre::eyre::{eyre, Result};
use dialoguer::{theme::ColorfulTheme, Password};
use std::{fs, path::PathBuf};

#[derive(Args, Debug, Clone)]
pub struct PasswordInput {
    #[clap(
        short,
        long,
        env = "AEGIS_PASSWORD_FILE",
        help = "Path to the password file"
    )]
    password_file: Option<PathBuf>,
    #[clap(
        long,
        env = "AEGIS_PASSWORD",
        help = "Password to unlock vault",
        conflicts_with = "password_file",
        hide_env_values = true
    )]
    password: Option<String>,
}

impl PasswordGetter for PasswordInput {
    fn get_password(&self) -> Result<String> {
        match (&self.password, &self.password_file) {
            (Some(password), None) => Ok(password.clone()),
            (None, Some(password_file)) => {
                let password = fs::read_to_string(password_file)?;
                Ok(password.trim().to_string())
            }
            // // TODO: Figure out how to best read STDIO
            // _ => Password::with_theme(&ColorfulTheme::default())
            //     .with_prompt("Insert Aegis Password")
            //     .interact()
            //     .map_err(|e| eyre!("Failed to get password: {}", e)),
            _ => Err(eyre!("No password provided")),
        }
    }
}
