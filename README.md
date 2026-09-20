# Majestic Observer API

Backend API для приложения Majestic Market Observer.

## Endpoints

### Публичные
- `GET /` — проверка работоспособности
- `GET /api/ping` — ping
- `POST /api/register` — регистрация
- `POST /api/login` — вход
- `POST /api/check-ban` — проверка бана

### Админ (требуется X-Admin-Key)
- `GET /api/admin/users` — список всех
- `GET /api/admin/stats` — статистика
- `POST /api/admin/user/{id}/role` — смена роли
- `POST /api/admin/user/{id}/ban` — бан/разбан
- `POST /api/admin/user/{id}/delete` — удаление

## Переменные окружения

- `DATABASE_URL` — строка подключения к PostgreSQL
- `ADMIN_KEY` — секретный ключ для админ-методов
