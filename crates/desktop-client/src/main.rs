//! XRPL Vault Desktop Application
//!
//! Точка входа Tauri приложения.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use xrpl_vault_desktop::{
    commands::*,
    state::{AppConfig, AppState},
};

fn main() {
    // Загружаем .env файл
    dotenv::dotenv().ok();
    // Инициализируем логирование
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("xrpl_vault_desktop=debug".parse().unwrap())
                .add_directive("tauri=info".parse().unwrap()),
        )
        .init();

    tracing::info!("Starting XRPL Vault Desktop...");

    // Загружаем конфигурацию
    let config = AppConfig::from_env();

    // Создаём состояние приложения
    let state = AppState::new(config).expect("Failed to create app state");

    // Запускаем Tauri
    tauri::Builder::default()
        .manage(state)
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            // Auth (основной flow)
            start_xaman_auth,
            wait_for_auth,
            start_key_derivation,
            wait_for_key_derivation,
            has_pre_keys,
            logout,
            is_authenticated,
            get_oracle_url,
            get_current_session,
            get_current_user,
            // Oracle Auth
            check_oracle_auth,
            get_oracle_auth_status,
            get_oracle_auth_status_extended,
            oracle_login_start,
            oracle_login_complete,
            oracle_login_wait,
            oracle_logout,
            oracle_refresh_token,
            get_device_fingerprint,
            // Balance & NFT (stubs)
            get_xrp_balance,
            list_my_nfts,
            get_my_nfts,
            // Encryption (stubs)
            encrypt_file,
            encrypt_bytes,
            // NFT Transactions (stubs)
            create_mint_transaction,
            verify_nft_ownership,
            // Transfer
            generate_transfer_key,
            claim_nft,
            wait_for_claim,
            get_incoming_offers,
            get_outgoing_offers,
            get_user_public_key,
            initiate_transfer,
            create_transfer_offer,
            wait_for_transfer_offer,
            complete_transfer,
            cancel_transfer,
            get_transfer_history,
            // Vault/Files
            get_my_files,
            upload_file,
            upload_files,
            download_file,
            request_file_access,
            delete_vault,
            burn_nft,
            wait_for_burn,
            // Secure Notes
            encrypt_secure_note,
            decrypt_secure_note,
            list_secure_notes,
            check_claim_status,
            cancel_secure_note_offer,
        ])
        .run(tauri::generate_context!())
        .expect("Error while running XRPL Vault");
}