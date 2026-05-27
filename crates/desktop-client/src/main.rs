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

use tauri::Manager;

fn safe_startup_error_message(message: &str) -> String {
    const MAX_MESSAGE_LEN: usize = 180;
    let mut safe = message
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();

    for forbidden in [
        "seed",
        "Seed",
        "private key",
        "private_key",
        "jwt",
        "JWT",
        "aes key",
        "aes_key",
        "plaintext",
        "recovery phrase",
        "mnemonic entropy",
        "tx_blob",
        "signature",
    ] {
        safe = safe.replace(forbidden, "[redacted]");
    }

    if safe.len() > MAX_MESSAGE_LEN {
        safe.truncate(MAX_MESSAGE_LEN);
    }

    safe
}

#[cfg(target_os = "linux")]
fn configure_linux_display_backend() {
    let display_present = std::env::var_os("DISPLAY").is_some();
    let wayland_display_present = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let gdk_backend_present = std::env::var_os("GDK_BACKEND").is_some();
    let should_force_x11 = display_present && wayland_display_present && !gdk_backend_present;

    if should_force_x11 {
        std::env::set_var("GDK_BACKEND", "x11");
    }

    tracing::info!(
        phase = "display_backend",
        status = if should_force_x11 {
            "x11_forced"
        } else {
            "unchanged"
        },
        display_present,
        wayland_display_present,
        gdk_backend_present,
        backend_forced = should_force_x11,
        "tauri_display_backend_configured"
    );
}

#[cfg(not(target_os = "linux"))]
fn configure_linux_display_backend() {}

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
    configure_linux_display_backend();

    // Загружаем конфигурацию
    let config = AppConfig::from_env();

    // Создаём состояние приложения
    let state = AppState::new(config).expect("Failed to create app state");

    tracing::info!(
        phase = "tauri_builder_setup",
        status = "started",
        display_present = std::env::var_os("DISPLAY").is_some(),
        wayland_display_present = std::env::var_os("WAYLAND_DISPLAY").is_some(),
        "tauri_builder_setup_started"
    );

    // Запускаем Tauri
    let builder = tauri::Builder::default()
        .manage(state)
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            tracing::info!(
                phase = "setup",
                status = "started",
                display_present = std::env::var_os("DISPLAY").is_some(),
                wayland_display_present = std::env::var_os("WAYLAND_DISPLAY").is_some(),
                "tauri_setup_started"
            );

            let window_count = app.webview_windows().len();
            let window_label = "main";

            match app.get_webview_window(window_label) {
                Some(window) => {
                    tracing::info!(
                        phase = "window_lookup",
                        status = "found",
                        window_label,
                        window_count,
                        result = true,
                        "tauri_window_lookup"
                    );

                    match window.show() {
                        Ok(()) => tracing::info!(
                            phase = "window_show",
                            status = "ok",
                            window_label,
                            result = true,
                            "tauri_window_show"
                        ),
                        Err(error) => tracing::warn!(
                            phase = "window_show",
                            status = "failed",
                            window_label,
                            result = false,
                            error_class = "window_show_failed",
                            error_message = %safe_startup_error_message(&error.to_string()),
                            "tauri_window_show"
                        ),
                    }

                    match window.set_focus() {
                        Ok(()) => tracing::info!(
                            phase = "window_focus",
                            status = "ok",
                            window_label,
                            result = true,
                            "tauri_window_focus"
                        ),
                        Err(error) => tracing::warn!(
                            phase = "window_focus",
                            status = "failed",
                            window_label,
                            result = false,
                            error_class = "window_focus_failed",
                            error_message = %safe_startup_error_message(&error.to_string()),
                            "tauri_window_focus"
                        ),
                    }
                },
                None => {
                    tracing::warn!(
                        phase = "window_lookup",
                        status = "missing",
                        window_label,
                        window_count,
                        result = false,
                        "tauri_window_lookup"
                    );
                },
            }

            tracing::info!(
                phase = "setup",
                status = "completed",
                "tauri_setup_completed"
            );
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Vaulted seed-based identity
            create_vaulted_wallet,
            restore_vaulted_wallet,
            validate_vaulted_seed,
            has_vaulted_wallet,
            get_auth_lifecycle_status,
            get_vaulted_xrpl_wallet,
            get_wallet_overview,
            get_xrpl_transaction_history,
            send_xrp_payment,
            check_xrpl_account_status,
            get_system_status,
            create_vaulted_nft_mint_qr_request,
            sign_vaulted_xrpl_qr_request,
            sign_vaulted_nft_mint_transaction,
            mint_vaulted_nft_locally,
            submit_vaulted_xrpl_tx_blob,
            register_minted_vault_object,
            finalize_pending_vault_mint,
            recover_pending_vault_mint,
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
            claim_nft,
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
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                tracing::info!(
                    phase = "window_event",
                    status = "close_requested",
                    window_label = window.label(),
                    "tauri_window_close_requested"
                );
            }
        });

    tracing::info!(
        phase = "tauri_build",
        status = "started",
        "tauri_build_started"
    );
    let app = builder
        .build(tauri::generate_context!())
        .expect("Error while building XRPL Vault");
    tracing::info!(
        phase = "tauri_build",
        status = "completed",
        "tauri_build_completed"
    );
    tracing::info!(phase = "tauri_run", status = "started", "tauri_run_started");

    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::Ready) {
            let window_label = "main";
            let window_count = app_handle.webview_windows().len();
            tracing::info!(
                phase = "run_event_ready",
                status = "started",
                window_count,
                "tauri_run_event_ready"
            );
            match app_handle.get_webview_window(window_label) {
                Some(window) => {
                    tracing::info!(
                        phase = "ready_window_lookup",
                        status = "found",
                        window_label,
                        window_count,
                        result = true,
                        "tauri_ready_window_lookup"
                    );
                    match window.show() {
                        Ok(()) => tracing::info!(
                            phase = "ready_window_show",
                            status = "ok",
                            window_label,
                            result = true,
                            "tauri_ready_window_show"
                        ),
                        Err(error) => tracing::warn!(
                            phase = "ready_window_show",
                            status = "failed",
                            window_label,
                            result = false,
                            error_class = "window_show_failed",
                            error_message = %safe_startup_error_message(&error.to_string()),
                            "tauri_ready_window_show"
                        ),
                    }
                    match window.set_focus() {
                        Ok(()) => tracing::info!(
                            phase = "ready_window_focus",
                            status = "ok",
                            window_label,
                            result = true,
                            "tauri_ready_window_focus"
                        ),
                        Err(error) => tracing::warn!(
                            phase = "ready_window_focus",
                            status = "failed",
                            window_label,
                            result = false,
                            error_class = "window_focus_failed",
                            error_message = %safe_startup_error_message(&error.to_string()),
                            "tauri_ready_window_focus"
                        ),
                    }
                },
                None => tracing::warn!(
                    phase = "ready_window_lookup",
                    status = "missing",
                    window_label,
                    window_count,
                    result = false,
                    "tauri_ready_window_lookup"
                ),
            }
        }
    });
}
