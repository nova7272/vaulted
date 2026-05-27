# Vaulted — быстрый старт

## 1. Подготовка

```bash
git clone <your-repo>
cd xrpl-vault
cp .env.example .env
```

Минимально для локальной разработки обычно достаточно PostgreSQL/Redis из `docker-compose.yml` и Oracle URL по умолчанию.

## 2. Настройка `.env`

```bash
DATABASE_URL=postgres://vaulted:vaulted@localhost:5432/vaulted
REDIS_URL=redis://localhost:6379
XRPL_NODE_URL=wss://s.altnet.rippletest.net:51233
XRPL_RPC_URL=https://s.altnet.rippletest.net:51234
ORACLE_URL=http://localhost:3000
```

Для live XRPL testnet flow нужен активированный testnet account. Seed/identity/wallet material создаётся локально Vaulted desktop клиентом и не должен храниться в `.env` для production.

## 3. Запуск инфраструктуры

```bash
make dev
```

Проверка:

```bash
docker compose ps
```

## 4. Запуск сервисов

Oracle:

```bash
make oracle
```

Storage node:

```bash
make storage
```

## 5. Health checks

```bash
curl http://localhost:3000/health
curl http://localhost:9001/health
```

## 6. Desktop UI checks

```bash
cd crates/desktop-client/ui
npm ci
npm run lint
npx tsc --noEmit --project tsconfig.json
npm run build
```

## 7. Rust checks

```bash
cd <repo-root>
cargo check --workspace
cargo test --workspace
```

## 8. Основные dev flows

- Create or restore Vaulted seed phrase.
- Check Wallet balance, receive QR, and Send XRP on testnet.
- Upload encrypted file.
- Generate deterministic NFT metadata preview.
- Locally sign XRPL NFT mint transaction.
- Finalize mint after Oracle ledger verification.
- Download/decrypt as owner.
- Transfer NFT/file access to a recipient.
- Accept the incoming recipient offer and decrypt after re-encryption.
- Share file access with recipient identity using fingerprint confirmation and `KeyEnvelope` grants.
- Approve device pairing / XRPL signing / file grants through signed QR payloads.

Текущий XRPL Grants runtime checkpoint и финальный checklist описаны в `docs/RUNTIME_VERIFICATION.md`.
