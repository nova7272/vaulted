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
    dotenvy::dotenv().ok();
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
            // Vaulted seed-based identity
            create_vaulted_wallet,
            restore_vaulted_wallet,
            validate_vaulted_seed,
            has_vaulted_wallet,
            get_vaulted_xrpl_wallet,
            check_xrpl_account_status,
            get_system_status,
            create_vaulted_nft_mint_qr_request,
            sign_vaulted_xrpl_qr_request,
            sign_vaulted_nft_mint_transaction,
            mint_vaulted_nft_locally,
            submit_vaulted_xrpl_tx_blob,
            register_minted_vault_object,
            finalize_pending_vault_mint,
            publish_vaulted_nft_metadata,
            generate_vaulted_nft_metadata_preview,
            start_vaulted_qr_login,
            poll_vaulted_qr_login,
            confirm_vaulted_qr_login,
            start_vaulted_device_pairing,
            poll_vaulted_device_pairing,
            confirm_vaulted_device_pairing,
            start_vaulted_xrpl_signing_request,
            poll_vaulted_xrpl_signing_request,
            confirm_vaulted_xrpl_signing_request,
            compute_recipient_encryption_key_fingerprint,
            get_vaulted_recipient_key_trust,
            trust_vaulted_recipient_key,
            revoke_vaulted_recipient_key_trust,
            list_vaulted_identity_devices,
            revoke_vaulted_identity_device,
            start_vaulted_file_grant_approval,
            start_vaulted_file_grant_for_nft,
            poll_vaulted_file_grant_approval,
            confirm_vaulted_file_grant_approval,
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
            get_incoming_offers,
            get_outgoing_offers,
            get_user_public_key,
            initiate_transfer,
            complete_transfer,
            cancel_transfer,
            get_transfer_history,
            // Vault/Files
            get_my_files,
            upload_file,
            upload_files,
            download_file,
            request_file_access,
            list_incoming_vaulted_grants,
            list_outgoing_vaulted_grants,
            preview_incoming_vaulted_grant,
            download_incoming_vaulted_grant,
            revoke_vaulted_grant,
            delete_vault,
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
