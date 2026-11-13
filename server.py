import hmac
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

from flask import Flask, g, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix


def env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"Не задана переменная окружения {name}")
    return value


BOT_TOKEN       = env("BOT_TOKEN", required=True)
DATABASE_URL    = env("DATABASE_URL", "")
DB_PATH         = env("DB_PATH", "balatro.db")
ALLOWED_ORIGINS = [o.strip() for o in env("ALLOWED_ORIGINS", required=True).split(",") if o.strip()]
RATE_STORAGE    = env("RATE_STORAGE", "memory://")
BEHIND_PROXY    = env("BEHIND_PROXY", "1") == "1"
AUTH_MAX_AGE    = int(env("AUTH_MAX_AGE", str(24 * 3600)))
ADMIN_IDS       = {int(x) for x in env("ADMIN_IDS", "").replace(" ", "").split(",") if x.isdigit()}

MAX_BLINDS        = 24
MAX_MONEY         = 20000
MIN_RUN_SECONDS   = 10
SECONDS_PER_BLIND = 8
RUN_TTL           = 2 * 24 * 3600

IS_PG = bool(DATABASE_URL)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("balatro")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096
if BEHIND_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

CORS(app, origins=ALLOWED_ORIGINS, methods=["GET", "POST"], allow_headers=["Content-Type"])

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=RATE_STORAGE,
    default_limits=["120 per minute"],
)


# ---------- База данных ----------
def get_db():
    if "db" not in g:
        if IS_PG:
            import psycopg
            from psycopg.rows import dict_row
            g.db = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        else:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
    return g.db


def q(sql, params=()):
    if not IS_PG:
        sql = sql.replace("%s", "?")
    return get_db().execute(sql, params)


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


SCHEMA = [
    """CREATE TABLE IF NOT EXISTS runs (
        id         TEXT PRIMARY KEY,
        user_id    BIGINT NOT NULL,
        name       TEXT NOT NULL,
        board_key  TEXT NOT NULL DEFAULT '',
        started    BIGINT NOT NULL,
        status     TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS scores (
        run_id     TEXT PRIMARY KEY,
        user_id    BIGINT NOT NULL,
        name       TEXT NOT NULL,
        board_key  TEXT NOT NULL DEFAULT '',
        score      BIGINT NOT NULL,
        week       TEXT NOT NULL,
        created    BIGINT NOT NULL
    )""",
]

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_scores_board_week ON scores (board_key, week, score DESC)",
    "CREATE INDEX IF NOT EXISTS idx_scores_board_all  ON scores (board_key, score DESC)",
]


def init_db():
    db = get_db()
    for stmt in SCHEMA + INDEXES:
        q(stmt)
    db.commit()


# ---------- Утилиты ----------
def now():
    return int(time.time())


def current_week():
    y, w, _ = datetime.now(timezone.utc).isocalendar()
    return f"{y}-W{w:02d}"


def clean_name(raw):
    name = re.sub(r"[\x00-\x1f]", "", str(raw or ""))[:32].strip()
    return name or "Игрок"


def verify_init_data(init_data: str):
    """Проверка подписи и свежести initData. Возвращает пользователя и ключ рейтинга."""
    data = dict(urllib.parse.parse_qsl(init_data, keep_blank_values=True))
    received = data.pop("hash", None)
    if not received:
        return None
    try:
        if now() - int(data.get("auth_date", 0)) > AUTH_MAX_AGE:
            return None
        user = json.loads(data["user"])
        user_id = int(user["id"])
        chat_raw = data.get("chat")
        chat_id = int(json.loads(chat_raw)["id"]) if chat_raw else None
    except (ValueError, KeyError, TypeError):
        return None

    check = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))
    secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    expected = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, received):
        return None

    board_key = f"chat:{chat_id}" if chat_id is not None else f"user:{user_id}"
    return {"id": user_id, "name": clean_name(user.get("first_name")), "board_key": board_key}


def read_user():
    body = request.get_json(silent=True) or {}
    return body, verify_init_data(str(body.get("initData", "")))


def admin_user(body):
    """Пользователь, если initData подписан Telegram и его ID есть в ADMIN_IDS."""
    user = verify_init_data(str(body.get("initData", "")))
    if not user or user["id"] not in ADMIN_IDS:
        return None
    return user


# ---------- Эндпоинты игрока ----------
@app.get("/health")
def health():
    return jsonify(ok=True)


@app.post("/run/start")
@limiter.limit("10 per minute")
def run_start():
    _, user = read_user()
    if not user:
        return jsonify(error="bad auth"), 403

    run_id = uuid.uuid4().hex
    q("""INSERT INTO runs (id, user_id, name, board_key, started, status)
         VALUES (%s, %s, %s, %s, %s, 'active')""",
      (run_id, user["id"], user["name"], user["board_key"], now()))
    q("UPDATE runs SET status = 'expired' WHERE status = 'active' AND started < %s",
      (now() - RUN_TTL,))
    get_db().commit()
    return jsonify(run_id=run_id)


@app.post("/run/finish")
@limiter.limit("10 per minute")
def run_finish():
    body, user = read_user()
    if not user:
        return jsonify(error="bad auth"), 403

    run_id = str(body.get("run_id", ""))
    try:
        cleared = int(body.get("cleared"))
        money = int(body.get("money"))
    except (TypeError, ValueError):
        return jsonify(error="bad numbers"), 400
    if not (0 <= cleared <= MAX_BLINDS and 0 <= money <= MAX_MONEY):
        return jsonify(error="out of range"), 400

    row = q("SELECT user_id, started, status, board_key, name FROM runs WHERE id = %s",
            (run_id,)).fetchone()
    if row is None or row["user_id"] != user["id"]:
        return jsonify(error="unknown run"), 404
    if row["status"] != "active":
        return jsonify(error="run already finished"), 409

    elapsed = now() - row["started"]
    if elapsed < MIN_RUN_SECONDS + cleared * SECONDS_PER_BLIND:
        log.warning("suspicious run user=%s elapsed=%s cleared=%s", user["id"], elapsed, cleared)
        q("UPDATE runs SET status = 'rejected' WHERE id = %s", (run_id,))
        get_db().commit()
        return jsonify(error="run too fast"), 422

    cur = q("UPDATE runs SET status = 'finished' WHERE id = %s AND status = 'active'", (run_id,))
    if cur.rowcount != 1:
        get_db().rollback()
        return jsonify(error="run already finished"), 409

    score = cleared * 1000 + money
    q("""INSERT INTO scores (run_id, user_id, name, board_key, score, week, created)
         VALUES (%s, %s, %s, %s, %s, %s, %s)""",
      (run_id, user["id"], row["name"], row["board_key"], score, current_week(), now()))
    get_db().commit()
    return jsonify(ok=True, score=score)


@app.post("/top")
@limiter.limit("60 per minute")
def top():
    body, user = read_user()
    if not user:
        return jsonify(error="bad auth"), 403

    period = body.get("period", "week")
    key = user["board_key"]
    if period == "week":
        rows = q("""SELECT MAX(name) AS name, MAX(score) AS score FROM scores
                    WHERE board_key = %s AND week = %s
                    GROUP BY user_id ORDER BY score DESC LIMIT 10""",
                 (key, current_week())).fetchall()
    elif period == "all":
        rows = q("""SELECT MAX(name) AS name, MAX(score) AS score FROM scores
                    WHERE board_key = %s
                    GROUP BY user_id ORDER BY score DESC LIMIT 10""",
                 (key,)).fetchall()
    else:
        return jsonify(error="bad period"), 400
    return jsonify([{"name": r["name"], "score": r["score"]} for r in rows])


# ---------- Админ-панель (только для ADMIN_IDS) ----------
@app.post("/admin/check")
def admin_check():
    body = request.get_json(silent=True) or {}
    return jsonify(is_admin=admin_user(body) is not None)


@app.post("/admin/stats")
@limiter.limit("30 per minute")
def admin_stats():
    body = request.get_json(silent=True) or {}
    if admin_user(body) is None:
        return jsonify(error="forbidden"), 403

    total_runs = q("SELECT COUNT(*) AS n FROM runs").fetchone()["n"]
    users = q("SELECT COUNT(DISTINCT user_id) AS n FROM runs").fetchone()["n"]
    by_status = [{"status": r["status"], "n": r["n"]} for r in
                 q("SELECT status, COUNT(*) AS n FROM runs GROUP BY status").fetchall()]
    top_rows = [{"run_id": r["run_id"], "name": r["name"], "board_key": r["board_key"],
                 "score": r["score"], "week": r["week"]} for r in
                q("SELECT run_id, name, board_key, score, week FROM scores ORDER BY score DESC LIMIT 20").fetchall()]
    return jsonify(total_runs=total_runs, users=users, runs_by_status=by_status, top=top_rows)


@app.post("/admin/delete_score")
@limiter.limit("30 per minute")
def admin_delete_score():
    body = request.get_json(silent=True) or {}
    if admin_user(body) is None:
        return jsonify(error="forbidden"), 403
    q("DELETE FROM scores WHERE run_id = %s", (str(body.get("run_id", "")),))
    get_db().commit()
    return jsonify(ok=True)


@app.post("/admin/clear_board")
@limiter.limit("10 per minute")
def admin_clear_board():
    body = request.get_json(silent=True) or {}
    if admin_user(body) is None:
        return jsonify(error="forbidden"), 403
    key = str(body.get("board_key", ""))
    if not key:
        return jsonify(error="no board_key"), 400
    q("DELETE FROM scores WHERE board_key = %s", (key,))
    get_db().commit()
    return jsonify(ok=True)


@app.errorhandler(429)
def rate_limited(_e):
    return jsonify(error="too many requests"), 429


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(port=8080)