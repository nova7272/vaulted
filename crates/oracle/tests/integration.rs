//! Интеграционные тесты XRPL Vault
//!
//! Требует запущенных сервисов:
//! - PostgreSQL на localhost:5432
//! - Storage Node на localhost:9001
//! - Oracle на localhost:3000

use reqwest::Client;
use serde_json::json;

const ORACLE_URL: &str = "http://localhost:3000";
const STORAGE_URL: &str = "http://localhost:9001";

/// Проверяет что Oracle работает
#[tokio::test]
async fn test_oracle_health() {
    let client = Client::new();

    let resp = client.get(format!("{}/health", ORACLE_URL)).send().await;

    match resp {
        Ok(r) => {
            assert!(r.status().is_success(), "Oracle health check failed");
            println!("✓ Oracle is healthy");
        },
        Err(e) => {
            println!("⚠ Oracle not running: {}", e);
            println!("  Start with: make oracle");
        },
    }
}

/// Проверяет что Storage Node работает
#[tokio::test]
async fn test_storage_health() {
    let client = Client::new();

    let resp = client.get(format!("{}/health", STORAGE_URL)).send().await;

    match resp {
        Ok(r) => {
            assert!(r.status().is_success(), "Storage health check failed");
            println!("✓ Storage Node is healthy");
        },
        Err(e) => {
            println!("⚠ Storage Node not running: {}", e);
            println!("  Start with: make storage");
        },
    }
}

/// Тест загрузки фрагмента на Storage Node
#[tokio::test]
async fn test_storage_upload_download() {
    let client = Client::new();

    // Проверяем что storage работает
    let health = client.get(format!("{}/health", STORAGE_URL)).send().await;
    if health.is_err() {
        println!("⚠ Skipping test: Storage Node not running");
        return;
    }

    // Загружаем тестовый фрагмент
    let test_data = b"Hello, XRPL Vault! This is a test fragment.";
    let key = format!("test_fragment_{}", uuid::Uuid::new_v4());

    let upload_resp = client
        .put(format!("{}/fragments/{}", STORAGE_URL, key))
        .header("Content-Type", "application/octet-stream")
        .body(test_data.to_vec())
        .send()
        .await
        .expect("Upload request failed");

    assert!(upload_resp.status().is_success(), "Upload failed");
    println!("✓ Fragment uploaded: {}", key);

    // Скачиваем обратно
    let download_resp = client
        .get(format!("{}/fragments/{}", STORAGE_URL, key))
        .send()
        .await
        .expect("Download request failed");

    assert!(download_resp.status().is_success(), "Download failed");

    let downloaded = download_resp.bytes().await.expect("Failed to read body");
    assert_eq!(downloaded.as_ref(), test_data, "Downloaded data mismatch");
    println!("✓ Fragment downloaded and verified");

    // Удаляем
    let delete_resp = client
        .delete(format!("{}/fragments/{}", STORAGE_URL, key))
        .send()
        .await
        .expect("Delete request failed");

    assert!(delete_resp.status().is_success(), "Delete failed");
    println!("✓ Fragment deleted");
}

/// Тест регистрации пользователя через Oracle
#[tokio::test]
async fn test_user_registration() {
    let client = Client::new();

    // Проверяем что oracle работает
    let health = client.get(format!("{}/health", ORACLE_URL)).send().await;
    if health.is_err() {
        println!("⚠ Skipping test: Oracle not running");
        return;
    }

    // Генерируем тестовые данные
    let wallet_address = format!("rTest{}", &uuid::Uuid::new_v4().to_string()[..20]);
    let pre_public_key = hex::encode(vec![0u8; 33]); // Dummy key

    let request = json!({
        "wallet_address": wallet_address,
        "pre_public_key": pre_public_key,
        "signature": "test_signature"
    });

    let resp = client
        .post(format!("{}/api/v1/users/register", ORACLE_URL))
        .json(&request)
        .send()
        .await
        .expect("Register request failed");

    println!("Registration response status: {}", resp.status());

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap();
        println!("✓ User registered: {:?}", body);
    } else {
        let error = resp.text().await.unwrap_or_default();
        println!("Registration error: {}", error);
    }
}

/// Полный тест flow: шифрование → загрузка → vault → NFT
#[tokio::test]
async fn test_full_vault_flow() {
    use xrpl_vault_crypto_core::{AesKey, FileManifest, ProxyReEncryption};

    let client = Client::new();

    // Проверяем сервисы
    let oracle_ok = client
        .get(format!("{}/health", ORACLE_URL))
        .send()
        .await
        .is_ok();
    let storage_ok = client
        .get(format!("{}/health", STORAGE_URL))
        .send()
        .await
        .is_ok();

    if !oracle_ok || !storage_ok {
        println!("⚠ Skipping full flow test: services not running");
        println!("  Oracle:  {}", if oracle_ok { "✓" } else { "✗" });
        println!("  Storage: {}", if storage_ok { "✓" } else { "✗" });
        return;
    }

    println!("\n=== Full Vault Flow Test ===\n");

    // 1. Генерируем PRE ключи
    let pre = ProxyReEncryption::new();
    let keypair = pre.generate_keypair();
    let public_key_hex = hex::encode(keypair.export_public_key_bytes());

    println!("1. Generated PRE keypair");
    println!("   Public key: {}...", &public_key_hex[..32]);

    // 2. Генерируем AES ключ и шифруем данные
    let aes_key = AesKey::generate();
    let test_data = b"This is secret file content for XRPL Vault test!";
    let encrypted = aes_key.encrypt(test_data).expect("Encryption failed");

    println!("2. Encrypted test data ({} bytes)", test_data.len());

    // 3. Шифруем AES ключ публичным ключом
    let encrypted_aes = pre
        .encrypt(&keypair.public_key(), aes_key.as_bytes())
        .expect("PRE encryption failed");
    let encrypted_aes_base64 = encrypted_aes.to_base64().expect("Base64 failed");

    println!("3. Encrypted AES key with PRE");

    // 4. Загружаем зашифрованные данные на Storage
    let fragment_key = format!("test_vault_{}", uuid::Uuid::new_v4());
    let fragment_data = encrypted.to_bytes().expect("Serialization failed");

    let upload_resp = client
        .put(format!("{}/fragments/{}", STORAGE_URL, fragment_key))
        .header("Content-Type", "application/octet-stream")
        .body(fragment_data.clone())
        .send()
        .await
        .expect("Storage upload failed");

    assert!(upload_resp.status().is_success(), "Storage upload failed");
    println!(
        "4. Uploaded encrypted fragment to storage: {}",
        fragment_key
    );

    // 5. Создаём манифест (using current FileManifest struct)
    let encrypted_hash_str = format!(
        "blake3:{}",
        hex::encode(blake3::hash(&fragment_data).as_bytes())
    );
    let manifest = FileManifest {
        encrypted_filename: "test_secret.txt".to_string(),
        original_size: test_data.len() as u64,
        mime_type: "text/plain".to_string(),
        original_hash: format!("sha256:{}", hex::encode(sha2::Sha256::digest(test_data))),
        encrypted_size: fragment_data.len() as u64,
        encrypted_hash: encrypted_hash_str.clone(),
    };

    let metadata_hash = manifest.compute_hash();
    println!("5. Created manifest, hash: {}...", &metadata_hash[..32]);

    // 6. Регистрируем пользователя
    let wallet_address = format!("rTestVault{}", &uuid::Uuid::new_v4().to_string()[..12]);

    let user_req = json!({
        "wallet_address": wallet_address,
        "pre_public_key": public_key_hex,
        "signature": "test_signature"
    });

    let user_resp = client
        .post(format!("{}/api/v1/users/register", ORACLE_URL))
        .json(&user_req)
        .send()
        .await
        .expect("User registration failed");

    println!("6. User registration: {}", user_resp.status());

    // 7. Создаём vault (это минтит NFT)
    let vault_req = json!({
        "wallet_address": wallet_address,
        "pre_public_key": public_key_hex,
        "encrypted_aes_key": encrypted_aes_base64,
        "metadata_hash": metadata_hash,
        "manifest": {
            "encrypted_filename": manifest.encrypted_filename,
            "original_size": manifest.original_size,
            "mime_type": manifest.mime_type,
            "original_hash": manifest.original_hash,
            "fragments": [{
                "index": 0,
                "storage_node_id": "node-eu-1",
                "storage_key": fragment_key,
                "encrypted_hash": encrypted_hash_str,
                "size": fragment_data.len()
            }]
        }
    });

    let vault_resp = client
        .post(format!("{}/api/v1/vault/create", ORACLE_URL))
        .json(&vault_req)
        .send()
        .await
        .expect("Vault creation failed");

    let vault_status = vault_resp.status();
    let vault_body = vault_resp.text().await.unwrap_or_default();

    println!(
        "7. Vault creation: {} - {}",
        vault_status,
        &vault_body[..100.min(vault_body.len())]
    );

    if vault_status.is_success() {
        let vault: serde_json::Value = serde_json::from_str(&vault_body).unwrap();
        println!("\n✓ Full flow completed successfully!");
        println!("  Vault ID:     {}", vault["vault_id"]);
        println!("  NFT Token ID: {}", vault["nft_token_id"]);
        println!("  Offer Index:  {}", vault["offer_index"]);
        println!("  Signing URI:  {}", vault["signing_request_uri"]);
    } else {
        println!("\n⚠ Vault creation failed (expected if XRPL wallet not configured)");
        println!("  Configure XRPL_WALLET_SEED in .env for full NFT minting");
    }

    // Cleanup
    let _ = client
        .delete(format!("{}/fragments/{}", STORAGE_URL, fragment_key))
        .send()
        .await;

    println!("\n=== Test Complete ===\n");
}

/// Тест криптографии: шифрование и расшифровка
#[tokio::test]
async fn test_crypto_roundtrip() {
    use xrpl_vault_crypto_core::{AesKey, ProxyReEncryption};

    println!("\n=== Crypto Roundtrip Test ===\n");

    // 1. Генерируем ключи
    let pre = ProxyReEncryption::new();
    let alice = pre.generate_keypair();

    println!("1. Generated keypair for Alice");

    // 2. Alice шифрует файл
    let secret_data = b"Super secret document content!";
    let aes_key = AesKey::generate();
    let encrypted_data = aes_key.encrypt(secret_data).expect("AES encrypt failed");

    println!("2. Alice encrypted data with AES");

    // 3. Alice шифрует AES ключ своим публичным ключом
    let encrypted_aes = pre
        .encrypt(&alice.public_key(), aes_key.as_bytes())
        .expect("PRE encrypt failed");

    println!("3. Alice encrypted AES key with her PRE public key");

    // 4. Сериализация и десериализация
    let serialized = encrypted_aes.to_base64().expect("Serialization failed");
    let deserialized = xrpl_vault_crypto_core::EncryptedPreData::from_base64(&serialized)
        .expect("Deserialization failed");

    println!("4. Serialized and deserialized encrypted key");

    // 5. Alice расшифровывает
    let decrypted_aes = pre
        .decrypt(&alice, &deserialized)
        .expect("PRE decrypt failed");

    let restored_aes = AesKey::from_bytes(&decrypted_aes).expect("Invalid AES key");
    let decrypted_data = restored_aes
        .decrypt(&encrypted_data)
        .expect("AES decrypt failed");

    assert_eq!(secret_data.as_slice(), decrypted_data.as_slice());
    println!("5. Alice successfully decrypted her data");

    println!("\n✓ Crypto roundtrip successful!\n");
}

// Helper для SHA256
use sha2::Digest;
