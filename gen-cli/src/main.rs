use hpos_config_core::{config::Seed, public_key, Config};

use clap::Parser;
use ed25519_dalek::*;
use failure::Error;
use rand::Rng;
use sha2::{Digest, Sha512Trunc256};
use std::{fs::File, io};

#[derive(Parser, Clone)]
#[command(about = "Creates HoloPortOS config file that contains seed and admin email/password.")]
struct ClapArgs {
    #[arg(
        long,
        value_parser,
        value_name = "EMAIL",
        help = "HoloPort admin email address"
    )]
    email: String,
    #[arg(
        long,
        value_parser,
        value_name = "PASSWORD",
        help = "HoloPort admin password"
    )]
    password: String,
    #[arg(
        long,
        value_parser,
        value_name = "CODE",
        help = "HoloPort registration code"
    )]
    registration_code: String,
    #[arg(long, value_parser, value_name = "STRING", help = "Revocation key")]
    revocation_key: Option<String>,
    #[arg(
        long,
        value_parser,
        value_name = "PATH",
        help = "Derivation path of the seed"
    )]
    derivation_path: Option<u32>,
    #[arg(
        long,
        value_parser,
        value_name = "NUMBER",
        help = "HoloPort Device bundle"
    )]
    device_bundle: Option<String>,
    #[arg(
        long,
        value_parser,
        value_name = "PATH",
        help = "Use SHA-512 hash of given file, truncated to 256 bits, as seed"
    )]
    seed_from: Option<String>,
}

// const USAGE: &str = "
// Usage: hpos-config-gen-cli --email EMAIL --password STRING --registration-code STRING [--derivation-path NUMBER] [--device-bundle STRING] [--seed-from PATH]
//        hpos-config-gen-cli --help

// Creates HoloPortOS config file that contains seed and admin email/password.

// Options:
//   --email EMAIL                 HoloPort admin email address
//   --password STRING             HoloPort admin password
//   --registration-code CODE      HoloPort admin password
//   --derivation-path NUMBER      Derivation path of the seed
//   --device-bundle STRING        Device Bundle
//   --seed-from PATH              Use SHA-512 hash of given file truncated to 256 bits as seed
// ";

// #[derive(Deserialize)]
// struct Args {
//     flag_email: String,
//     flag_password: String,
//     flag_registration_code: String,
//     flag_revocation_pub_key: VerifyingKey,
//     flag_derivation_path: Option<u32>,
//     flag_device_bundle: Option<String>,
//     flag_seed_from: Option<PathBuf>,
// }

fn main() -> Result<(), Error> {
    let args = ClapArgs::parse();

    let seed = match args.seed_from {
        None => rand::thread_rng().gen::<Seed>(),
        Some(path) => {
            let mut hasher = Sha512Trunc256::new();
            let mut file = File::open(path)?;
            io::copy(&mut file, &mut hasher)?;

            let seed: Seed = hasher.result().into();
            seed
        }
    };

    let derivation_path = if let Some(derivation_path) = args.derivation_path {
        derivation_path
    } else {
        hpos_config_core::utils::DEFAULT_DERIVATION_PATH_V2
    };

    let device_bundle = if let Some(device_bundle) = args.device_bundle {
        device_bundle
    } else {
        let passphrase = "pass";
        let locked_device_bundle_encoded_bytes =
            hpos_config_core::utils::generate_device_bundle(passphrase, Some(derivation_path))?;

        base64::encode(&locked_device_bundle_encoded_bytes)
    };

    let secret_key = SigningKey::from_bytes(&seed);
    let revocation_key = match &args.revocation_key {
        None => VerifyingKey::from(&secret_key),
        Some(rk) => {
            let public_key_bytes: &[u8; PUBLIC_KEY_LENGTH] = rk.as_bytes().try_into()?;
            VerifyingKey::from_bytes(public_key_bytes)?
        }
    };

    let (config, public_key) = Config::new(
        // email: String,
        args.email,
        // password: String,
        args.password,
        // registration_code: String,
        args.registration_code,
        // revocation_pub_key: VerifyingKey,
        revocation_key,
        // derivation_path: String,
        derivation_path.to_string(),
        // device_bundle: String,
        device_bundle,
        // device_pub_key: VerifyingKey,
        VerifyingKey::from(&secret_key),
    )?;
    eprintln!("{}", public_key::to_url(&public_key)?);
    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}
