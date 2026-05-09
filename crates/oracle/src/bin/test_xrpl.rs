//! Тест XRPL сервиса

use xrpl_mithril::wallet::{Wallet, Seed, Algorithm};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Генерируем seed и wallet
    let seed = Seed::random();
    let encoded_seed = seed.encode();
    let wallet = Wallet::from_seed(&seed, Algorithm::Secp256k1)?;

    println!("Generated wallet:");
    println!("  Address: {}", wallet.classic_address());
    println!("  Seed: {}", encoded_seed);

    // Используем XrplService
    let config = xrpl_vault_oracle::xrpl::XrplConfig {
        node_url: "https://s.altnet.rippletest.net:51234".to_string(),
        node_urls: vec![],
        wallet_seed: Some(encoded_seed.clone()),
    };

    let xrpl = xrpl_vault_oracle::xrpl::XrplService::with_wallet(config)?;
    println!("\nXrplService created!");
    println!("Oracle address: {}", xrpl.oracle_address().unwrap());

    // Запросим faucet
    println!("\nRequesting testnet funds...");
    let client = reqwest::Client::new();
    let resp = client.post("https://faucet.altnet.rippletest.net/accounts")
        .json(&serde_json::json!({
            "destination": wallet.classic_address()
        }))
        .send()
        .await?;

    let faucet_result: serde_json::Value = resp.json().await?;
    println!("Faucet: {} XRP", faucet_result["amount"]);

    // Подождём
    println!("Waiting for ledger...");
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // Баланс
    let balance = xrpl.get_balance(wallet.classic_address()).await?;
    println!("Balance: {} XRP", balance);

    if balance > 15.0 {
        // Минтим NFT
        println!("\nMinting NFT...");
        let result = xrpl.mint_nft("xvault:test123456789abcdef", 0).await?;
        println!("✅ Minted NFT: {}", result.nft_token_id);
        println!("   TX: {}", result.tx_hash);

        // Создаём offer
        println!("\nCreating sell offer...");
        let offer = xrpl.create_sell_offer(
            &result.nft_token_id,
            "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
        ).await?;
        println!("✅ Created offer: {}", offer.offer_index);
        println!("   TX: {}", offer.tx_hash);

        // Баланс после
        let balance_after = xrpl.get_balance(wallet.classic_address()).await?;
        println!("\nBalance after: {} XRP (spent: {:.6} XRP)", balance_after, balance - balance_after);
    } else {
        println!("Not enough balance");
    }

    Ok(())
}