# XRPL Vault - Быстрый старт

## 🚀 Запуск за 5 минут

### 1. Подготовка

```bash
# Клонируем репозиторий
git clone <your-repo>
cd xrpl-vault

# Копируем конфигурацию
cp .env.example .env
```

### 2. Настройка .env

Отредактируйте `.env` и добавьте:

```bash
# Обязательно для NFT минтинга:
# Создайте тестовый кошелёк на https://xrpl.org/xrp-testnet-faucet.html
XRPL_WALLET_SEED=sEdXXXXXXXXXXXXXXXXXXXXXXXXXX

# Для Xaman авторизации (опционально для тестов):
# Получите на https://apps.xaman.dev
XAMAN_API_KEY=your-key
XAMAN_API_SECRET=your-secret
```

### 3. Запуск инфраструктуры

```bash
# Запускаем PostgreSQL + Redis и применяем миграции
make dev
```

Проверяем:
```bash
# PostgreSQL должен быть на порту 5432
docker compose ps
```

### 4. Запуск сервисов

**Терминал 1 - Oracle:**
```bash
make oracle
```

Должны увидеть:
```
Starting XRPL Vault Oracle v0.1.0
Database connected
Migrations complete: 3 total, 0 applied, 3 skipped
Oracle listening on http://127.0.0.1:3000
```

**Терминал 2 - Storage Node:**
```bash
make storage
```

Должны увидеть:
```
Starting storage node node-eu-1 on 0.0.0.0:9001
Loaded 0 existing fragments
```

### 5. Проверка

```bash
# Health checks
curl http://localhost:3000/health
# {"status":"ok","version":"0.1.0","database":"connected"}

curl http://localhost:9001/health
# {"status":"healthy","node_id":"node-eu-1","fragments_count":0}
```

### 6. Тестирование

```bash
# Unit тесты
cargo test

# Интеграционные тесты (требуют запущенных сервисов)
cargo test --package xrpl-vault-oracle --test integration -- --nocapture
```

## 📁 Структура портов

| Сервис | Порт | Описание |
|--------|------|----------|
| PostgreSQL | 5432 | База данных |
| Redis | 6379 | Кэш/очереди |
| Oracle | 3000 | API сервер |
| Storage Node | 9001 | Хранение фрагментов |
| Adminer | 8080 | Web UI для БД (dev-tools) |
| Redis Commander | 8081 | Web UI для Redis (dev-tools) |

## 🔧 Полезные команды

```bash
# Показать все команды
make help

# Перезапустить БД с нуля
make db-reset

# Открыть psql shell
make db-shell

# Просмотр логов
docker compose logs -f postgres

# Остановить всё
make down

# Удалить все данные
make clean
```

## 🐛 Решение проблем

### PostgreSQL не запускается

```bash
# Проверьте статус
docker compose ps

# Посмотрите логи
docker compose logs postgres

# Попробуйте перезапустить
docker compose down
docker compose up -d postgres
```

### Oracle не подключается к БД

```bash
# Проверьте DATABASE_URL в .env
echo $DATABASE_URL

# Должно быть:
# postgres://xrpl_vault:dev_password_change_me@localhost:5432/xrpl_vault

# Проверьте доступность PostgreSQL
docker compose exec postgres pg_isready -U xrpl_vault
```

### Ошибки миграций

```bash
# Сбросьте БД
make db-reset

# Или вручную
docker compose exec postgres psql -U xrpl_vault -d xrpl_vault -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
make migrate
```

### NFT минтинг не работает

1. Проверьте XRPL_WALLET_SEED в .env
2. Убедитесь что на кошельке есть XRP (минимум 15 XRP)
3. Проверьте логи Oracle на ошибки XRPL

```bash
# Проверить баланс кошелька (замените адрес)
curl -X POST https://s.altnet.rippletest.net:51234 \
  -H "Content-Type: application/json" \
  -d '{"method":"account_info","params":[{"account":"rYOUR_ADDRESS"}]}'
```

## 📝 Следующие шаги

1. **Desktop Client** - собрать Tauri приложение:
   ```bash
   cd crates/desktop-client
   cargo tauri dev
   ```

2. **Документация API** - см. README.md

3. **Тестирование полного flow** - см. `tests/integration.rs`
