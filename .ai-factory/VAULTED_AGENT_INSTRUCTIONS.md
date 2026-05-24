# VAULTED_AGENT_INSTRUCTIONS.md

# Инструкция для AI-агента разработки Vaulted

## 1. Роль агента

Ты — автономный инженерный агент проекта **Vaulted**. Твоя задача — непрерывно доводить проект до production-ready MVP для XRPL Grants: внедрять изменения, проверять их локально, исправлять ошибки, коммитить только после успешных проверок и поддерживать репозиторий в стабильном состоянии.

Проект представляет собой:

- Rust workspace;
- Tauri desktop client;
- React/TypeScript frontend;
- Oracle backend;
- storage-node;
- PostgreSQL/Redis через Docker Compose;
- XRPL testnet integration;
- encrypted file vault + XRPL wallet + NFT ownership/transfer flow.

Главная цель: полностью рабочий end-to-end flow от регистрации пользователя до шифрования файла, загрузки, mint NFT, передачи NFT другому пользователю и re-encryption доступа.

---

## 2. Абсолютные правила

### 2.1. Никогда не коммить сломанный код

Коммит разрешён только если успешно прошли проверки, релевантные изменённым частям проекта.

Минимальный набор для Rust-изменений:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

Минимальный набор для frontend-изменений:

```bash
cd crates/desktop-client/ui
npm run lint
npm run typecheck
npm run build
npm audit --audit-level=high
cd ../../..
```

Для security/release задач:

```bash
make security-audit-strict
```

Если проверка не проходит, агент обязан исправить проблему до коммита.

### 2.2. Не логировать секреты

Запрещено логировать, выводить в UI, сохранять в файлы или коммитить:

- seed phrase;
- private key;
- XRPL family seed;
- JWT / Oracle token;
- tx_blob;
- AES key;
- encrypted AES key, если это не публично допустимый ciphertext в уже существующей модели;
- plaintext содержимое файлов;
- recovery phrase;
- raw mnemonic entropy.

Для диагностики разрешено логировать только безопасные значения:

- classic address;
- public key fingerprint;
- engine_result;
- engine_result_message;
- tx_hash;
- boolean accepted;
- metadata_uri length;
- endpoint status code;
- truncated non-secret hashes.

### 2.3. Один PR / один коммит — одна логическая задача

Не смешивать UI polish, seed security, XRPL submit diagnostics, wallet tab, QR login, storage fixes и dependency updates. Каждое изменение должно быть маленьким, проверяемым и откатываемым.

### 2.4. Не делать logout / reset в runtime-сессии без разрешения

Если пользователь сообщил, что потерял seed phrase текущего аккаунта, агент не должен предлагать logout, clear app data, reset local state, создание нового wallet вместо диагностики или удаление текущей сессии.

---

## 3. Рабочий цикл агента

Каждая задача выполняется по циклу:

1. Синхронизировать репозиторий.
2. Создать ветку или работать в текущей ветке, если пользователь явно разрешил.
3. Изучить код и связанные места.
4. Составить краткий план.
5. Внести минимальные изменения.
6. Запустить проверки.
7. Исправить ошибки.
8. Повторить проверки.
9. Сделать коммит.
10. Запушить.
11. Кратко отчитаться: что сделано, какие проверки прошли, какой commit hash.

Команды начала работы:

```bash
cd ~/vaulted
git status --short
git pull --ff-only origin main
```

Для новой задачи:

```bash
git checkout -b feat/<short-task-name>
```

Перед коммитом:

```bash
git status --short
git diff --stat
git diff --check
```

---

## 4. Формат коммита

Хорошие сообщения:

```bash
git commit -m "Accept sha256 NFT metadata URIs"
git commit -m "Expose XRPL mint submit errors"
git commit -m "Enforce 12 word seed policy"
git commit -m "Add wallet balance and receive screen"
```

Запрещённые сообщения:

```text
fix
updates
misc
wip
final
changes
```

После коммита:

```bash
git status
git log --oneline -5
```

После push:

```bash
git push origin <branch-or-main>
```

---

## 5. Стандартные проверки

### 5.1. Полная проверка проекта

```bash
cd ~/vaulted

cargo fmt --all --check
cargo check --workspace
cargo test --workspace
make security-audit-strict

cd crates/desktop-client/ui
npm run lint
npm run typecheck
npm run build
npm audit --audit-level=high
cd ../../..
```

### 5.2. Быстрая проверка после backend-only правок

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

### 5.3. Быстрая проверка после Oracle-only правок

```bash
cargo fmt --all --check
cargo check -p xrpl-vault-oracle
cargo test -p xrpl-vault-oracle
```

### 5.4. Быстрая проверка после desktop Rust правок

```bash
cargo fmt --all --check
cargo check -p xrpl-vault-desktop
cargo test -p xrpl-vault-desktop
```

### 5.5. Быстрая проверка после frontend-only правок

```bash
cd crates/desktop-client/ui
npm run lint
npm run typecheck
npm run build
npm audit --audit-level=high
cd ../../..
```

---

## 6. Runtime dev environment

### 6.1. Поднять инфраструктуру

```bash
cd ~/vaulted
docker compose up -d postgres redis
docker compose ps
docker exec xrpl-vault-postgres pg_isready -U xrpl_vault -d xrpl_vault
```

### 6.2. Запустить Oracle

```bash
cd ~/vaulted
set -a
source .env
set +a
cargo run -p xrpl-vault-oracle --bin oracle
```

Health:

```bash
curl -s http://127.0.0.1:3000/health
```

### 6.3. Запустить storage-node

```bash
cd ~/vaulted
set -a
source .env
set +a
REQUIRE_AUTH=false cargo run -p xrpl-vault-storage-node --bin storage-node
```

Health:

```bash
curl -s http://127.0.0.1:9001/health
```

### 6.4. Запустить frontend / desktop

Frontend dev:

```bash
cd ~/vaulted/crates/desktop-client/ui
npm install
npm run dev
```

Desktop:

```bash
cd ~/vaulted
set -a
source .env
set +a
RUST_LOG=info cargo run -p xrpl-vault-desktop
```

Логирование в файл:

```bash
cd ~/vaulted
set -a
source .env
set +a
RUST_LOG=info cargo run -p xrpl-vault-desktop 2>&1 | tee /tmp/vaulted-desktop.log
```

---

## 7. Текущая критическая задача: завершить mint flow

### 7.1. Известное состояние

- Upload работает.
- Oracle token валиден.
- XRPL account активирован.
- `/nft/sha256:<hash>/metadata.json` должен возвращать `200 OK`.
- Если metadata endpoint возвращает `400 Invalid NFT ID`, это bug публичного NFT route.
- Если `account_tx` не содержит `NFTokenMint`, значит mint transaction не дошла до ledger или submit был отклонён до ledger inclusion.
- UI не должен показывать только generic `Blockchain transaction failed`.

### 7.2. Проверить metadata URL

```bash
curl -I 'http://127.0.0.1:3000/nft/sha256:<HASH>/metadata.json'
```

Ожидается:

```text
HTTP/1.1 200 OK
content-type: application/json
```

### 7.3. Проверить XRPL account

```bash
export VAULTED_WALLET='<CLASSIC_ADDRESS>'

curl -s -X POST https://s.altnet.rippletest.net:51234/ \
  -H 'Content-Type: application/json' \
  -d "{
    \"method\": \"account_info\",
    \"params\": [{
      \"account\": \"$VAULTED_WALLET\",
      \"ledger_index\": \"validated\",
      \"strict\": true
    }]
  }" | python3 -m json.tool
```

### 7.4. Проверить account NFTs

```bash
curl -s -X POST https://s.altnet.rippletest.net:51234/ \
  -H 'Content-Type: application/json' \
  -d "{
    \"method\": \"account_nfts\",
    \"params\": [{
      \"account\": \"$VAULTED_WALLET\",
      \"ledger_index\": \"validated\"
    }]
  }" | python3 -m json.tool
```

### 7.5. Проверить последние транзакции

```bash
curl -s -X POST https://s.altnet.rippletest.net:51234/ \
  -H 'Content-Type: application/json' \
  -d "{
    \"method\": \"account_tx\",
    \"params\": [{
      \"account\": \"$VAULTED_WALLET\",
      \"ledger_index_min\": -1,
      \"ledger_index_max\": -1,
      \"limit\": 10
    }]
  }" | python3 -m json.tool
```

### 7.6. Добавить безопасную диагностику submit

Если mint падает, агент должен добавить логирование:

- `engine_result`;
- `engine_result_message`;
- `tx_hash`;
- `accepted`;
- account;
- metadata URI length.

Запрещено логировать:

- `tx_blob`;
- seed;
- private key;
- JWT;
- AES keys.

Acceptance criteria:

```text
- XrplClient::submit logs accepted/rejected submit result.
- submit_vaulted_xrpl_tx_blob logs command-level result.
- Non-tes result returns to frontend with engine_result and engine_result_message.
- UI displays specific XRPL failure.
- account_tx contains NFTokenMint after successful mint.
- account_nfts contains newly minted NFT.
```

---

## 8. Seed phrase policy

### 8.1. Требование

В production MVP разрешена только **12-word seed phrase**.

Запрещено:

- генерация 24 слов;
- выбор advanced 24-word mode;
- неявная генерация mnemonic из предсказуемого источника;
- `Math.random`;
- timestamp-based seed;
- UUID-based seed;
- device fingerprint as entropy.

### 8.2. Secure generation

Seed phrase должна генерироваться через BIP-39 и OS CSPRNG.

Rust-критерии:

```text
- использовать audited BIP-39 crate;
- использовать OS randomness через getrandom/rand_core;
- 128 bits entropy для 12 слов;
- zeroize/secrecy для чувствительных данных там, где возможно;
- seed phrase не пишется в logs;
- seed phrase не попадает в panic/debug output.
```

### 8.3. Acceptance criteria

```text
- Create wallet генерирует ровно 12 слов.
- Restore принимает только 12 слов.
- UI не содержит 24-word option.
- Тесты проверяют генерацию 12 слов.
- Тесты отклоняют 6/18/24 слов, если policy строго 12 слов.
- Все seed-sensitive logs удалены.
```

---

## 9. Auth screen requirements

Экран входа должен содержать три основных действия:

```text
1. Sign in with seed phrase
2. Sign in with QR code
3. Create new wallet
```

UX требования:

```text
- Create wallet ведёт в seed backup ceremony.
- Continue disabled до подтверждения “I saved this seed phrase offline”.
- Copy seed phrase требует warning/confirmation.
- Seed phrase показывается только в backup step.
- После завершения onboarding seed phrase больше не показывается.
- Restore flow имеет clear validation errors.
- QR login показывает expiration timer, retry и cancel.
```

---

## 10. QR login requirements

QR login должен быть рабочим, а не mock.

Flow:

```text
Desktop creates challenge.
Phone scans QR.
Phone shows approval screen.
Phone signs challenge.
Oracle verifies signature.
Desktop receives approved session.
Desktop unlocks identity/session without receiving seed phrase.
```

Security:

```text
- challenge expires in 60–120 seconds;
- single-use nonce;
- domain separation: VAULTED_QR_LOGIN_V1;
- device binding;
- replay protection;
- Oracle cannot forge approval;
- seed phrase never leaves phone/local device.
```

Tests:

```text
- expired QR rejected;
- replay rejected;
- wrong device rejected;
- invalid signature rejected;
- successful approval unlocks desktop session.
```

---

## 11. Wallet tab requirements

Добавить вкладку **Wallet**.

MVP:

```text
- XRP balance;
- wallet classic address;
- copy address;
- receive QR;
- send XRP;
- transaction history;
- XRPL connection status;
- testnet/mainnet badge.
```

Send XRP flow:

```text
1. Enter destination.
2. Enter amount.
3. Validate classic address.
4. Validate amount.
5. Validate reserve and fee.
6. Show confirmation screen.
7. Sign locally.
8. Submit to XRPL.
9. Show tx hash and status.
```

Acceptance criteria:

```text
- Balance loads from account_info.
- Send XRP works on testnet.
- Reserve is respected.
- Destination tag warning exists where needed.
- Transaction history uses account_tx.
- No seed/private key leaves local app.
```

---

## 12. File vault flow requirements

Full successful flow:

```text
1. Register user.
2. Derive identity and XRPL wallet from seed.
3. Register identity in Oracle.
4. Encrypt file locally.
5. Upload encrypted payload to storage.
6. Publish public NFT metadata.
7. Mint ownership NFT locally.
8. Finalize mint in Oracle.
9. Display vault object.
10. Download/decrypt as owner.
11. Transfer NFT to another user.
12. Re-encrypt file key for recipient.
13. Recipient accepts transfer.
14. Recipient decrypts file.
```

Security criteria:

```text
- plaintext file never reaches Oracle/storage-node;
- AES key never stored plaintext server-side;
- only encrypted payload/fragments are uploaded;
- recipient receives re-encrypted key envelope;
- ownership verified through XRPL;
- old owner access behavior is explicit and tested.
```

---

## 13. UI/UX production criteria

Design target:

```text
Linear + Phantom Wallet + Proton Drive + XRPL-native identity
```

Required navigation:

```text
Vaults
Upload
Wallet
Transfers
Activity
Settings
```

UI principles:

```text
- dark premium interface;
- modern cards;
- clear empty states;
- progress for every async action;
- retry buttons;
- no raw stack traces;
- no raw blockchain jargon without explanation;
- compact status center for Oracle / Storage / XRPL;
- all irreversible actions require confirmation.
```

Error mapping examples:

```text
actNotFound -> Wallet is not funded yet.
tecINSUFF_RESERVE -> Not enough XRP reserve.
tefPAST_SEQ -> Transaction sequence is stale. Retry.
terQUEUED -> Transaction queued. Checking status.
Request timeout -> XRPL connection timed out. Try again.
Missing authorization -> Session expired. Sign in again.
```

---

## 14. XRPL Grants MVP acceptance checklist

Before marking MVP ready:

```text
[ ] Docker compose starts Postgres/Redis.
[ ] Oracle starts and /health responds.
[ ] Storage-node starts and /health responds.
[ ] Desktop starts.
[ ] Create wallet generates secure 12-word seed.
[ ] Restore by seed works.
[ ] QR login works or demo-safe QR flow is clearly implemented.
[ ] Wallet tab shows XRP balance.
[ ] Receive QR works.
[ ] Send XRP works on testnet.
[ ] Upload encrypts file locally.
[ ] Encrypted payload uploads.
[ ] Public metadata URL returns 200.
[ ] Mint NFT succeeds.
[ ] NFT appears in account_nfts.
[ ] Vault object finalizes in Oracle.
[ ] Download/decrypt works as owner.
[ ] Transfer NFT/file access to another user works.
[ ] Recipient decrypts after re-encryption.
[ ] make security-audit-strict passes.
[ ] cargo test --workspace passes.
[ ] frontend lint/typecheck/build passes.
[ ] README/demo script updated.
```

---

## 15. Runtime verification document

After successful runtime milestone, update or create:

```text
docs/RUNTIME_VERIFICATION.md
```

Template:

```markdown
# Runtime verification

Date:

## Environment

- Oracle:
- Storage node:
- XRPL network:
- XRPL node:
- Postgres/Redis:

## Checks

- [ ] Oracle health
- [ ] Storage health
- [ ] Desktop launch
- [ ] Create wallet
- [ ] Restore wallet
- [ ] QR login
- [ ] Wallet balance
- [ ] Send XRP
- [ ] Upload
- [ ] Metadata URL 200
- [ ] Mint NFT
- [ ] Finalize Oracle state
- [ ] Transfer NFT/file
- [ ] Recipient decrypt

## Notes

## Known issues
```

---

## 16. How to handle failures

### 16.1. If tests fail

Do not commit. Fix and rerun.

### 16.2. If cargo fmt fails

```bash
cargo fmt --all
cargo fmt --all --check
```

### 16.3. If npm audit shows moderate vulnerability

If command was:

```bash
npm audit --audit-level=high
```

and exit code is `0`, it is not a blocker for high-level audit. Document it if relevant.

### 16.4. If XRPL timeout appears

Transient logs like this are not automatically fatal:

```text
XRPL WebSocket error: IO error: Connection timed out
Connected to XRPL node
```

But UI must not show raw timeout as fatal if reconnect succeeds.

### 16.5. If mint fails

Do all diagnostics:

```text
curl -I '<metadata_uri>'
account_info
account_tx
account_nfts
desktop submit logs
DevTools Console
```

Do not guess. Fix based on `engine_result`.

---

## 17. Reporting format after each task

Agent response must include:

```text
Done:
- ...

Changed files:
- ...

Checks:
- cargo fmt --all --check: pass/fail
- cargo check --workspace: pass/fail
- cargo test --workspace: pass/fail
- npm lint/typecheck/build: pass/fail
- make security-audit-strict: pass/fail

Commit:
<hash> <message>

Next:
- ...
```

If something failed:

```text
Blocked:
- command:
- error:
- likely cause:
- next action:
```

---

## 18. Immediate next tasks

Work in this order:

```text
1. Finish XRPL mint submit diagnostics.
2. Fix actual NFTokenMint failure based on engine_result.
3. Commit sha256 metadata URI fix + submit diagnostics/fix.
4. Verify mint end-to-end.
5. Enforce 12-word seed only.
6. Add wallet tab.
7. Finish QR login.
8. Complete transfer/re-encryption.
9. Polish UI for XRPL Grants demo.
10. Update runtime verification and README.
```

---

## 19. Final definition of production-ready MVP

Vaulted MVP is ready only when a fresh user can do this without developer intervention:

```text
Create wallet with 12-word seed
→ back up seed
→ see XRP wallet
→ receive testnet XRP
→ upload encrypted file
→ mint NFT
→ see NFT/vault
→ send XRP
→ transfer NFT/file access to another user
→ recipient decrypts file
```

All of this must pass with clean tests and no sensitive logs.
