# XRPL Vault

Децентрализованное зашифрованное хранилище файлов с NFT-based access control на блокчейне XRPL.

## Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│                    Desktop Client (Tauri)                    │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────┐ │
│  │  Auth   │  │ Crypto  │  │  XRPL   │  │  Oracle Client  │ │
│  │ (Xaman) │  │AES+ECIES│  │  Client │  │    (HTTP)       │ │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────────┬────────┘ │
│       │            │            │                 │          │
│  🔒 Приватные ключи НИКОГДА не покидают устройство!         │
└───────┼────────────┼────────────┼─────────────────┼──────────┘
        │            │            │                 │
        │ QR Auth    │            │ NFT mint        │ Encrypted
        ▼            │            ▼                 ▼ files
┌───────────────┐    │    ┌───────────────┐  ┌─────────────────┐
│ Xaman Wallet  │    │    │     XRPL      │  │  Oracle Server  │
│   (Mobile)    │    │    │  (XLS-20 NFT) │  │   (PRE Proxy)   │
└───────────────┘    │    └───────────────┘  └────────┬────────┘
                     │                                │
                     │                                ▼
                     │                       ┌─────────────────┐
                     │                       │ Storage Nodes   │
                     │                       │  (Distributed)  │
                     │                       └─────────────────┘
                     │
            Шифрование происходит ТОЛЬКО здесь
```

## Ключевые принципы безопасности

1. **Шифрование на клиенте** — AES-ключ генерируется локально, файлы шифруются до отправки
2. **Приватные ключи не покидают устройство** — Oracle никогда не видит приватные ключи
3. **Proxy Re-Encryption** — при передаче NFT Oracle перешифровывает, не видя содержимого
4. **NFT = Access Control** — владение NFT = право на расшифровку файлов

## Структура проекта

```
xrpl-vault/
├── crates/
│   ├── crypto-core/       # Shared криптографические примитивы
│   │   ├── aes.rs         # AES-256-GCM
│   │   ├── pre.rs         # Proxy Re-Encryption
│   │   └── hash.rs        # SHA-256, BLAKE3
│   │
│   ├── desktop-client/    # Tauri приложение (клиент)
│   │   ├── src/
│   │   │   ├── auth/      # Xaman QR авторизация
│   │   │   ├── crypto/    # Шифрование/расшифровка файлов
│   │   │   ├── xrpl/      # XRPL WebSocket, NFT операции
│   │   │   ├── oracle/    # HTTP клиент к Oracle
│   │   │   └── storage/   # Keystore (безопасное хранение ключей)
│   │   └── ui/            # Frontend (Svelte/Vue/React)
│   │
│   ├── oracle/            # Сервер-оракул (Axum)
│   │   └── src/           # PRE proxy, metadata, storage manager
│   │
│   └── storage-node/      # Серверы хранения
│
├── migrations/            # SQL схема
├── docker-compose.yml     # PostgreSQL + Redis
└── Makefile              # Dev commands
```

## Быстрый старт

```bash
# Клонировать репозиторий
git clone https://github.com/your-org/xrpl-vault.git
cd xrpl-vault

# Запустить dev environment
docker-compose up -d

# Собрать проект
cargo build

# Запустить тесты
cargo test

# Запустить oracle (dev mode)
cargo run -p xrpl-vault-oracle
```

## Пример использования крипто-модуля

```rust
use xrpl_vault_crypto::{
    aes::AesKey,
    pre::{PreKeyPair, ProxyReEncryption},
};

fn main() {
    let pre = ProxyReEncryption::new();
    
    // Генерируем ключи Alice и Bob
    let alice = PreKeyPair::generate(&pre);
    let bob = PreKeyPair::generate(&pre);
    
    // Alice шифрует файл
    let aes_key = AesKey::generate();
    let encrypted_file = aes_key.encrypt(b"secret document").unwrap();
    
    // Alice шифрует AES-ключ для себя
    let encrypted_aes = pre.encrypt(&alice.public_key(), aes_key.as_bytes()).unwrap();
    
    // При передаче NFT: Alice генерирует re-encryption key
    let re_key = pre.generate_re_key(&alice, &bob.public_key()).unwrap();
    
    // Oracle перешифровывает (не видя AES-ключа!)
    let re_encrypted = pre.re_encrypt(&re_key, &encrypted_aes).unwrap();
    
    // Bob расшифровывает AES-ключ
    let bob_aes_bytes = pre.decrypt_re_encrypted(&bob, &re_encrypted).unwrap();
    let bob_aes_key = AesKey::from_bytes(&bob_aes_bytes).unwrap();
    
    // Bob расшифровывает файл
    let decrypted = bob_aes_key.decrypt(&encrypted_file).unwrap();
    assert_eq!(b"secret document".as_slice(), decrypted.as_slice());
}
```

## Конфигурация

### Переменные окружения

| Переменная | Описание | По умолчанию |
|------------|----------|--------------|
| `DATABASE_URL` | PostgreSQL connection string | - |
| `REDIS_URL` | Redis connection string | - |
| `XRPL_NODE_URL` | XRPL WebSocket URL | `wss://s.altnet.rippletest.net:51233` |
| `RUST_LOG` | Уровень логирования | `info` |

## Лицензия

MIT

## Contributing

См. [CONTRIBUTING.md](CONTRIBUTING.md)
