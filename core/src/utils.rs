/// Generate a new device bundle and lock it with the given passphrase.
pub fn generate_device_bundle(
    passphrase: &str,
    maybe_derivation_path: Option<u32>,
) -> Result<Box<[u8]>, failure::Error> {
    let rt = tokio::runtime::Runtime::new()?;
    let passphrase = sodoken::BufRead::from(passphrase.as_bytes());
    rt.block_on(async move {
        let master = hc_seed_bundle::UnlockedSeedBundle::new_random()
            .await
            .unwrap();

        let derivation_path = maybe_derivation_path.unwrap_or(DEFAULT_DERIVATION_PATH_V2);

        let device_bundle = master.derive(derivation_path).await.unwrap();
        device_bundle
            .lock()
            .add_pwhash_cipher(passphrase)
            .lock()
            .await
    })
    .map_err(Into::into)
}

pub const DEFAULT_DERIVATION_PATH_V2: u32 = 3;
