# app.py — Majestic Observer API
import os
import hashlib
import secrets
from datetime import datetime
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, request, jsonify

app = Flask(__name__)

# ============ НАСТРОЙКИ ============
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "change_me_please")

# Render отдаёт URL в формате postgres://, psycopg2 требует postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)


# ============ БАЗА ДАННЫХ ============
def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")


def init_db():
    """Создаёт таблицу users при первом запуске."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'trader',
            is_banned INTEGER DEFAULT 0,
            hwid TEXT DEFAULT '',
            login_count INTEGER DEFAULT 0,
            last_login TEXT DEFAULT '',
            last_ip TEXT DEFAULT '',
            created_at TEXT DEFAULT ''
        )
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("✅ Таблица users готова")


def hash_pwd(password, salt):
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def now_iso():
    return datetime.utcnow().isoformat()


# ============ ДЕКОРАТОР АДМИНА ============
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-Admin-Key", "")
        if key != ADMIN_KEY:
            return jsonify({"ok": False, "error": "Нет доступа"}), 403
        return f(*args, **kwargs)
    return wrapper


# ============ ИНИЦИАЛИЗАЦИЯ ============
try:
    init_db()
except Exception as e:
    print(f"⚠️ Ошибка init_db: {e}")


# ============ ПРОВЕРКА ============
@app.route("/")
def index():
    return jsonify({
        "service": "Majestic Observer API",
        "status": "ok",
        "version": "1.0.0"
    })


@app.route("/api/ping")
def ping():
    return jsonify({"ok": True, "time": now_iso()})


# ============ РЕГИСТРАЦИЯ ============
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    hwid = data.get("hwid") or ""

    if not username or not password:
        return jsonify({"ok": False, "error": "Заполни логин и пароль"}), 400
    if len(username) < 3:
        return jsonify({"ok": False, "error": "Логин минимум 3 символа"}), 400
    if len(password) < 4:
        return jsonify({"ok": False, "error": "Пароль минимум 4 символа"}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"ok": False, "error": "Логин занят"}), 400

    salt = secrets.token_hex(16)
    pwd_hash = hash_pwd(password, salt)
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")

        cur.execute("""
        INSERT INTO users (username, password_hash, salt, password_plain, role,
                           hwid, created_at, last_login, last_ip, login_count)
        VALUES (%s, %s, %s, %s, 'trader', %s, %s, %s, %s, 1)
        RETURNING id
    """, (username, pwd_hash, salt, password, hwid, now_iso(), now_iso(), ip))
    uid = cur.fetchone()["id"]
    conn.commit()
    cur.close()
    conn.close()

    print(f"🆕 Регистрация: {username} (#{uid})")

    return jsonify({
        "ok": True,
        "user": {
            "id": uid,
            "username": username,
            "role": "trader",
            "is_banned": False
        }
    })


# ============ ВХОД ============
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    hwid = data.get("hwid") or ""

    if not username or not password:
        return jsonify({"ok": False, "error": "Заполни все поля"}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    row = cur.fetchone()

    if not row:
        cur.close(); conn.close()
        return jsonify({"ok": False, "error": "Пользователь не найден"}), 404

    if row["is_banned"]:
        cur.close(); conn.close()
        return jsonify({"ok": False, "error": "Аккаунт заблокирован"}), 403

    if hash_pwd(password, row["salt"]) != row["password_hash"]:
        cur.close(); conn.close()
        return jsonify({"ok": False, "error": "Неверный пароль"}), 401

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")

    # Обновляем статистику
    cur.execute("""
        UPDATE users
        SET last_login = %s, last_ip = %s,
            login_count = login_count + 1,
            hwid = CASE WHEN hwid = '' THEN %s ELSE hwid END
        WHERE id = %s
    """, (now_iso(), ip, hwid, row["id"]))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({
        "ok": True,
        "user": {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "is_banned": bool(row["is_banned"])
        }
    })


# ============ ПРОВЕРКА БАНА ============
@app.route("/api/check-ban", methods=["POST"])
def check_ban():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"ok": False, "error": "Нет логина"}), 400

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT is_banned, role FROM users WHERE username = %s", (username,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return jsonify({"ok": False, "error": "Не найден"}), 404

    return jsonify({
        "ok": True,
        "is_banned": bool(row["is_banned"]),
        "role": row["role"]
    })


# ============ АДМИН: СПИСОК ПОЛЬЗОВАТЕЛЕЙ ============
@app.route("/api/admin/users")
@admin_required
def admin_users():
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT id, username, role, is_banned, hwid,
               login_count, last_login, last_ip, created_at
        FROM users
        ORDER BY id ASC
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()

    users = []
    for r in rows:
        users.append({
            "id": r["id"],
            "username": r["username"],
            "role": r["role"],
            "is_banned": bool(r["is_banned"]),
            "hwid": r["hwid"],
            "login_count": r["login_count"],
            "last_login": r["last_login"],
            "last_ip": r["last_ip"],
            "created_at": r["created_at"],
        })

    return jsonify({"ok": True, "users": users, "total": len(users)})


# ============ АДМИН: СМЕНИТЬ РОЛЬ ============
@app.route("/api/admin/user/<int:uid>/role", methods=["POST"])
@admin_required
def admin_set_role(uid):
    data = request.get_json(silent=True) or {}
    role = data.get("role") or "trader"

    allowed = ["owner", "admin", "moderator", "premium", "trader", "guest"]
    if role not in allowed:
        return jsonify({"ok": False, "error": "Неверная роль"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET role = %s WHERE id = %s", (role, uid))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"ok": True, "message": f"Роль изменена на {role}"})


# ============ АДМИН: БАН / РАЗБАН ============
@app.route("/api/admin/user/<int:uid>/ban", methods=["POST"])
@admin_required
def admin_ban(uid):
    data = request.get_json(silent=True) or {}
    ban = bool(data.get("ban", True))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_banned = %s WHERE id = %s",
                (1 if ban else 0, uid))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"ok": True, "message": "Забанен" if ban else "Разбанен"})


# ============ АДМИН: УДАЛИТЬ ============
@app.route("/api/admin/user/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_delete(uid):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (uid,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "message": "Пользователь удалён"})


# ============ АДМИН: СТАТИСТИКА ============
@app.route("/api/admin/stats")
@admin_required
def admin_stats():
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT COUNT(*) as c FROM users")
    total = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) as c FROM users WHERE is_banned = 1")
    banned = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) as c FROM users WHERE role != 'trader'")
    privileged = cur.fetchone()["c"]

    cur.close()
    conn.close()

    return jsonify({
        "ok": True,
        "total": total,
        "banned": banned,
        "active": total - banned,
        "privileged": privileged
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
