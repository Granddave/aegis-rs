use aegis_vault_utils::otp::{calculate_remaining_time, generate_otp, Entry};
use color_eyre::eyre::Result;

#[derive(Debug, serde::Serialize)]
struct CalculatedOtp {
    issuer: String,
    name: String,
    otp: String,
    remaining_time: i32,
}

fn entries_to_json(entries: &[Entry]) -> Result<()> {
    let output: Vec<CalculatedOtp> = entries
        .iter()
        .map(|entry| {
            Ok(CalculatedOtp {
                issuer: entry.issuer.clone(),
                name: entry.name.clone(),
                otp: generate_otp(&entry.info)?,
                remaining_time: calculate_remaining_time(&entry.info)?,
            })
        })
        .collect::<Result<Vec<CalculatedOtp>>>()?;
    if output.is_empty() {
        eprintln!("No entries found");
    } else {
        println!("{}", serde_json::to_string_pretty(&output)?);
    }
    Ok(())
}
