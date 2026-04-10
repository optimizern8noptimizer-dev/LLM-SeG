<div align="center">

<img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white"/>
<img src="https://img.shields.io/badge/SQLite-embedded-003B57?style=for-the-badge&logo=sqlite&logoColor=white"/>
<img src="https://img.shields.io/badge/OpenAI--Compatible-API-412991?style=for-the-badge&logo=openai&logoColor=white"/>

<br/><br/>


```
 ██╗     ██╗     ███╗   ███╗    ███████╗███████╗ ██████╗
 ██║     ██║     ████╗ ████║    ██╔════╝██╔════╝██╔════╝
 ██║     ██║     ██╔████╔██║    ███████╗█████╗  ██║
 ██║     ██║     ██║╚██╔╝██║    ╚════██║██╔══╝  ██║
 ███████╗███████╗██║ ╚═╝ ██║    ███████║███████╗╚██████╗
 ╚══════╝╚══════╝╚═╝     ╚═╝    ╚══════╝╚══════╝ ╚═════╝

       GATEWAY  ·  SECURITY  ·  COMPLIANCE
```

# LLM Security Gateway

**Корпоративный прокси-шлюз для языковых моделей**

Единая точка контроля над всеми LLM-запросами в организации —
с фильтрацией по стандартам безопасности, управлением доступом и полным audit trail.

[🚀 Быстрый старт](#-быстрый-старт) · [📖 Документация](#-api) · [🛡 Правила безопасности](#-правила-безопасности) · [🖥 Скриншоты](#-веб-интерфейс)

---

</div>

## Содержание

- [Что это и зачем](#-что-это-и-зачем)
- [Архитектура](#-архитектура)
- [Возможности](#-возможности)
- [Быстрый старт](#-быстрый-старт)
- [Конфигурация](#-конфигурация)
- [API](#-api)
- [Правила безопасности](#-правила-безопасности)
- [Веб-интерфейс](#-веб-интерфейс)
- [Структура проекта](#-структура-проекта)
- [Стек технологий](#-стек-технологий)

---

## 🎯 Что это и зачем

При прямом использовании LLM-провайдеров организации сталкиваются с серьёзными проблемами:

| Проблема | Последствие |
|---|---|
| Реальные API-ключи хранятся в приложениях | Компрометация ключа = компрометация всего аккаунта |
| Сотрудники передают в LLM номера карт, паспортные данные | Нарушение PCI DSS, GDPR, 152-ФЗ |
| Нет логов запросов | Невозможно пройти аудит регулятора |
| Prompt injection остаётся незамеченным | Атаки на системный промпт без обнаружения |
| Смена провайдера = переработка кода | Vendor lock-in |

**LLM Security Gateway решает все эти проблемы одним компонентом**, не требуя изменений в клиентском коде.

```
 Клиентские приложения         LLM Security Gateway          LLM-провайдеры
 ─────────────────────         ────────────────────          ───────────────
                               ┌──────────────────┐
  Python SDK ──────────────►  │  1. Auth check    │ ──────► OpenAI
  Node.js ─────────────────►  │  2. Rate limit    │
  curl ────────────────────►  │  3. Filter (23✓)  │ ──────► Anthropic
  Open WebUI ──────────────►  │  4. Route model   │
  LangChain ───────────────►  │  5. Audit log     │ ──────► Ollama / Custom
                               └──────────────────┘
```

---

## 🏗 Архитектура

```
llm-gateway/
│
├── app.py              # Flask-приложение: HTTP-роутинг, JWT, Admin REST API
├── gateway.py          # Маршрутизация к провайдерам, конвертация форматов
├── database.py         # SQLite ORM: все сущности, статистика, audit log
├── filter_engine.py    # Движок контентной фильтрации: 23 правила
├── setup.py            # Мастер первоначальной настройки
├── requirements.txt    # Python-зависимости
├── install.sh          # Автоустановщик для Ubuntu/Debian
├── llm-gateway.service # Systemd unit
├── config.yaml         # Конфигурация (генерируется setup.py)
├── gateway.db          # SQLite база данных (создаётся автоматически)
└── static/
    └── index.html      # Web Admin SPA (vanilla JS, Chart.js)
```

**Поток запроса через шлюз:**

```
POST /v1/chat/completions
  │
  ├─► [1] Проверка Bearer-токена → api_keys
  ├─► [2] Rate limit check → rate_limit_tracker (скользящее окно, 1 мин)
  ├─► [3] Контентная фильтрация → filter_engine.py (regex, 23 правила)
  │         ├─ action=block → HTTP 451 + запись в filter_logs
  │         └─ action=flag  → запись в filter_logs, запрос продолжается
  ├─► [4] Поиск маршрута → model_routes → providers
  ├─► [5] Проксирование → httpx (OpenAI / Anthropic / Custom)
  └─► [6] Логирование → request_logs (статус, токены, латентность)
```

---

## ⚡ Возможности

### 🔀 Маршрутизация и проксирование
- Виртуальные имена моделей — клиент пишет `"model": "gpt-4o"`, шлюз отправляет на нужный провайдер
- Поддержка нескольких провайдеров одновременно: **OpenAI**, **Anthropic**, **Ollama**, любой OpenAI-compatible endpoint
- Автоматическая конвертация формата Anthropic Messages API ↔ OpenAI API
- Приоритизация маршрутов

### 🔑 Управление доступом
- Виртуальные клиентские ключи формата `sk-gw-*` — реальные ключи провайдеров хранятся только на сервере
- Индивидуальные RPM-лимиты на каждый ключ
- Мгновенный отзыв доступа без перезапуска

### 🛡 Контентная фильтрация
- **23 встроенных правила** на основе OWASP LLM Top 10, PCI DSS v4.0, GDPR, EU AI Act Art.5, NIST AI RMF
- Три режима реакции: `block` (HTTP 451), `flag` (логировать + продолжить), `log`
- Кастомные regex-правила через веб-интерфейс
- Тест паттерна прямо в интерфейсе

### 📊 Аудит и мониторинг
- Полный лог каждого запроса: ключ, модель, статус, латентность, токены, ошибка
- Dashboard с графиками за 24 часа и 7 дней
- Отдельный журнал срабатываний фильтров с указанием совпавшего фрагмента
- Статистика по токенам и моделям

---

## 🚀 Быстрый старт

### Требования

- Python 3.10+
- pip

### Установка

```bash
# 1. Клонировать репозиторий
git clone https://github.com/your-username/llm-security-gateway.git
cd llm-security-gateway

# 2. Создать виртуальное окружение
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows (PowerShell)
venv\Scripts\Activate.ps1

# 3. Установить зависимости
pip install -r requirements.txt

# 4. Первоначальная настройка (создаёт config.yaml)
python setup.py

# 5. Запуск
python app.py
```

Откройте браузер: **http://localhost:8080**

### Автоматическая установка (Ubuntu/Debian)

```bash
sudo bash install.sh
```

Скрипт создаёт системного пользователя, настраивает systemd-сервис и запускает шлюз.

---

## ⚙️ Конфигурация

`config.yaml` генерируется командой `python setup.py`:

```yaml
server:
  host: 0.0.0.0
  port: 8080
  debug: false          # Никогда не включать в production

admin:
  secret_key: <64-byte random hex>    # JWT-секрет
  password_hash: <sha256 of password> # Хэш пароля admin-панели

database:
  path: gateway.db      # Путь к SQLite-файлу

gateway:
  timeout_seconds: 120  # Таймаут запроса к провайдеру
```

> ⚠️ `config.yaml` содержит секретный ключ. Добавьте в `.gitignore` и установите `chmod 600`.

### Смена пароля администратора

```bash
python -c "
import hashlib, yaml
pw = input('New password: ')
c = yaml.safe_load(open('config.yaml'))
c['admin']['password_hash'] = hashlib.sha256(pw.encode()).hexdigest()
yaml.dump(c, open('config.yaml', 'w'))
print('Done')
"
```

---

## 📡 API

Шлюз реализует **OpenAI-совместимый API**. Подключается без изменений из любого клиента.

### Аутентификация

```
Authorization: Bearer sk-gw-<ваш_ключ>
```

### Endpoints

| Метод | Путь | Описание |
|---|---|---|
| `POST` | `/v1/chat/completions` | Chat completions (OpenAI-формат) |
| `GET` | `/v1/models` | Список доступных виртуальных моделей |
| `POST` | `/api/auth/login` | Получение JWT для admin-панели |
| `GET` | `/api/admin/stats` | Статистика за 24 часа |
| `GET/POST` | `/api/admin/keys` | Управление API-ключами |
| `GET/POST` | `/api/admin/providers` | Управление провайдерами |
| `GET/POST` | `/api/admin/routes` | Управление маршрутами |
| `GET/POST` | `/api/admin/filter/rules` | Правила фильтрации |
| `GET` | `/api/admin/filter/logs` | Журнал срабатываний |

### Примеры

**Python SDK:**
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="sk-gw-ВАШ_КЛЮЧ"
)

response = client.chat.completions.create(
    model="gpt-4o",          # виртуальное имя из маршрутов
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Привет!"}
    ]
)
print(response.choices[0].message.content)
```

**curl:**
```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer sk-gw-ВАШ_КЛЮЧ" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hello!"}],
    "max_tokens": 256
  }'
```

**LangChain:**
```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    base_url="http://localhost:8080/v1",
    api_key="sk-gw-ВАШ_КЛЮЧ",
    model="gpt-4o"
)
```

### Коды ошибок

| HTTP | type | Причина |
|---|---|---|
| `401` | `auth_error` | Отсутствует или недействительный ключ |
| `403` | `auth_error` | Ключ отключён |
| `429` | `rate_limit_error` | Превышен RPM-лимит |
| `451` | `content_filter_error` | Запрос заблокирован правилом безопасности |
| `502` | `gateway_error` | Ошибка при запросе к upstream-провайдеру |

---

## 🛡 Правила безопасности

23 встроенных правила, активных по умолчанию:

### OWASP LLM Top 10 (2025)

| Правило | Категория | Действие | Серьёзность |
|---|---|---|---|
| Prompt Injection – Ignore Instructions | LLM01 | `block` | critical |
| Prompt Injection – Role Override / DAN | LLM01 | `block` | critical |
| Prompt Injection – System Prompt Extraction | LLM01 | `block` | high |
| Sensitive Info – Credentials in Request | LLM06 | `flag` | high |
| Harmful – CBRN Weapons | LLM09 | `block` | critical |
| Harmful – Malware / Ransomware Creation | LLM09 | `block` | critical |
| Harmful – Phishing Content | LLM09 | `block` | high |
| Harmful – Self-Harm Instructions | LLM09 | `block` | critical |

### PCI DSS v4.0

| Правило | Требование | Действие |
|---|---|---|
| Card Number (PAN) — Visa/MC/Amex/JCB | Req. 3.3 | `block` |
| CVV / CVV2 / CVC | Req. 3.2.1 | `block` |
| Track Data (магнитная полоса) | Req. 3.2.1 | `block` |

### GDPR / 152-ФЗ

| Правило | Стандарт | Действие |
|---|---|---|
| Паспорт РФ | Art. 5 / 152-ФЗ | `flag` |
| СНИЛС | 152-ФЗ | `flag` |
| ИНН | 152-ФЗ | `flag` |
| IBAN | Art. 5 | `flag` |
| Email (массовая передача) | Art. 5(1)(c) | `flag` |

### EU AI Act Art. 5

| Правило | Статья | Действие |
|---|---|---|
| CSAM | Art. 5(1)(b) | `block` |
| Биометрическая слежка | Art. 5(1)(h) | `block` |
| Социальный рейтинг | Art. 5(1)(c) | `block` |
| Скрытая манипуляция | Art. 5(1)(a) | `flag` |

### NIST AI RMF / Security

| Правило | Стандарт | Действие |
|---|---|---|
| Fake News Generation | Govern 1.1 | `block` |
| Deepfake Request | Map 2.1 | `flag` |
| SQL Injection Payload | OWASP A03 | `flag` |
| SSTI Payload | OWASP A03 | `flag` |

---

## 🖥 Веб-интерфейс

Admin-панель доступна по адресу `http://localhost:8080/` после запуска.

### Разделы

**Dashboard** — метрики за 24 часа: запросы, токены, ошибки, латентность. Графики по часам и за 7 дней.

**API Ключи** — создание и отзыв клиентских ключей, настройка RPM-лимитов, статистика использования.

**Провайдеры** — добавление LLM-провайдеров (OpenAI, Anthropic, Ollama, Custom). API-ключи провайдеров хранятся в зашифрованном виде.

**Маршруты** — маппинг виртуальных имён моделей на реальные модели у провайдеров.

**Безопасность** — управление 23 встроенными правилами (включение/отключение тумблером), добавление кастомных regex-правил с тестированием паттерна. Журнал всех срабатываний.

**Логи** — таблица всех входящих запросов с фильтрацией и пагинацией.

**API Docs** — примеры curl и Python SDK для подключения клиентов.

---

## 📁 Структура проекта

```
llm-gateway/
│
├── app.py                  # Flask: маршруты API, JWT-middleware, SPA-serving
│   ├── /v1/chat/completions
│   ├── /v1/models
│   ├── /api/auth/login
│   └── /api/admin/*
│
├── gateway.py              # Проксирование к провайдерам
│   ├── OpenAI/Custom       # httpx → /v1/chat/completions
│   └── Anthropic           # httpx → /v1/messages + конвертация формата
│
├── database.py             # SQLite ORM (без SQLAlchemy)
│   ├── api_keys            # Клиентские ключи + RPM-лимиты
│   ├── providers           # Провайдеры + их API-ключи
│   ├── model_routes        # Маппинг виртуальная модель → провайдер
│   ├── request_logs        # Журнал всех запросов
│   ├── filter_rules        # Правила безопасности
│   ├── filter_logs         # Журнал срабатываний
│   └── rate_limit_tracker  # Счётчики RPM (TTL 5 мин)
│
├── filter_engine.py        # Движок фильтрации
│   ├── BUILTIN_RULES[]     # 23 встроенных правила (regex)
│   ├── FilterEngine.check()
│   └── FilterResult        # blocked, action, rule_name, severity, standard
│
└── static/index.html       # Admin SPA
    ├── Dashboard (Chart.js)
    ├── API Keys CRUD
    ├── Providers CRUD
    ├── Routes CRUD
    ├── Security (rules + filter logs)
    └── API Docs
```

---

## 🔧 Стек технологий

| Компонент | Технология |
|---|---|
| **Backend** | Python 3.10+, Flask 3.0 |
| **WSGI** | Gunicorn (production) |
| **HTTP-клиент** | httpx (async-ready) |
| **Auth** | PyJWT (HS256, 24h TTL) |
| **База данных** | SQLite с WAL-режимом |
| **Frontend** | Vanilla JavaScript SPA |
| **Графики** | Chart.js 4.4 |
| **Стили** | CSS Custom Properties, dark theme |

---

## 🔒 Безопасность

### Рекомендации для production

```bash
# Nginx reverse proxy с TLS
server {
    listen 443 ssl;
    server_name gateway.example.com;

    # Ограничить admin-панель по IP
    location /api/admin/ {
        allow 192.168.1.0/24;
        deny all;
        proxy_pass http://127.0.0.1:8080;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_read_timeout 180s;
    }
}
```

> ⚠️ Никогда не запускайте с `server.debug: true` в production.  
> ⚠️ Не открывайте порт 8080 напрямую в интернет.

---

## 📋 Зависимости

```
flask>=3.0.0
flask-cors>=4.0.0
pyjwt>=2.8.0
httpx>=0.27.0
pyyaml>=6.0.1
gunicorn>=22.0.0
```

---

## 📄 Лицензия

MIT License — свободное использование в коммерческих и некоммерческих проектах.

---

<div align="center">

**LLM Security Gateway** · Python · Flask · SQLite · OpenAI-compatible

*Корпоративный контроль над LLM — без компромиссов*

</div>

