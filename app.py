import os
import re
from decimal import Decimal, InvalidOperation

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")


def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")

    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor
    )


def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS demo_accounts (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    account_number TEXT NOT NULL UNIQUE,
                    balance NUMERIC(14, 2) NOT NULL DEFAULT 0,
                    is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                ALTER TABLE demo_accounts
                ADD COLUMN IF NOT EXISTS
                is_blocked BOOLEAN NOT NULL DEFAULT FALSE
            """)


def authorized():
    if not ADMIN_TOKEN:
        return False

    supplied = request.headers.get("Authorization", "")
    return supplied == f"Bearer {ADMIN_TOKEN}"


@app.before_request
def protect_admin_operations():
    if request.path.startswith("/api/admin/"):
        if not authorized():
            return jsonify({"error": "Unauthorized"}), 401


@app.route("/")
def home():
    return send_from_directory(".", "admin.html")


@app.route("/api/status")
def status():
    return jsonify({
        "status": "success",
        "message": "BOKKA FOX API is running"
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/accounts", methods=["GET"])
def list_accounts():
    try:
        init_db()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, account_number,
                           balance, is_blocked, created_at
                    FROM demo_accounts
                    ORDER BY id DESC
                """)
                rows = cur.fetchall()

        for row in rows:
            row["balance"] = str(row["balance"])
            row["created_at"] = row["created_at"].isoformat()

        return jsonify(rows)

    except Exception:
        app.logger.exception("Could not list accounts")
        return jsonify({
            "error": "Database operation failed"
        }), 500


@app.route("/api/admin/accounts", methods=["POST"])
def add_account():
    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip()
    account_number = str(
        data.get("account_number", "")
    ).strip()

    if not username:
        return jsonify({
            "error": "Username is required"
        }), 400

    # رقم الحساب يجب أن يتكون من 7 أرقام بالضبط
    if not re.fullmatch(r"[0-9]{7}", account_number):
        return jsonify({
            "error": "Account number must contain exactly 7 digits"
        }), 400

    try:
        balance = Decimal(str(data.get("balance", "0")))

        if not balance.is_finite() or balance < 0:
            raise InvalidOperation

    except (InvalidOperation, ValueError):
        return jsonify({
            "error": "Invalid balance"
        }), 400

    try:
        init_db()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO demo_accounts
                    (username, account_number, balance)
                    VALUES (%s, %s, %s)
                    RETURNING id, username, account_number,
                              balance, is_blocked
                """, (username, account_number, balance))

                row = cur.fetchone()

        row["balance"] = str(row["balance"])
        return jsonify(row), 201

    except psycopg2.errors.UniqueViolation:
        return jsonify({
            "error": "Username or account number already exists"
        }), 409

    except Exception:
        app.logger.exception("Could not add account")
        return jsonify({
            "error": "Database operation failed"
        }), 500


@app.route(
    "/api/admin/accounts/<int:account_id>/balance",
    methods=["PATCH"]
)
def update_balance(account_id):
    data = request.get_json(silent=True) or {}

    try:
        balance = Decimal(str(data.get("balance", "")))

        if not balance.is_finite() or balance < 0:
            raise InvalidOperation

    except (InvalidOperation, ValueError):
        return jsonify({"error": "Invalid balance"}), 400

    try:
        init_db()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE demo_accounts
                    SET balance = %s
                    WHERE id = %s
                    RETURNING id, username, account_number, balance
                """, (balance, account_id))

                row = cur.fetchone()

        if row is None:
            return jsonify({"error": "Account not found"}), 404

        row["balance"] = str(row["balance"])
        return jsonify(row)

    except Exception:
        app.logger.exception("Could not update balance")
        return jsonify({
            "error": "Database operation failed"
        }), 500


@app.route(
    "/api/admin/accounts/<int:account_id>/block",
    methods=["PATCH"]
)
def block_account(account_id):
    data = request.get_json(silent=True) or {}
    blocked = data.get("blocked")

    if not isinstance(blocked, bool):
        return jsonify({
            "error": "blocked must be true or false"
        }), 400

    try:
        init_db()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE demo_accounts
                    SET is_blocked = %s
                    WHERE id = %s
                    RETURNING id, username, is_blocked
                """, (blocked, account_id))

                row = cur.fetchone()

        if row is None:
            return jsonify({"error": "Account not found"}), 404

        return jsonify(row)

    except Exception:
        app.logger.exception("Could not change block status")
        return jsonify({
            "error": "Database operation failed"
        }), 500


@app.route(
    "/api/admin/accounts/<int:account_id>",
    methods=["DELETE"]
)
def delete_account(account_id):
    try:
        init_db()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM demo_accounts
                    WHERE id = %s
                    RETURNING id
                """, (account_id,))

                row = cur.fetchone()

        if row is None:
            return jsonify({"error": "Account not found"}), 404

        return jsonify({
            "status": "success",
            "deleted_id": row["id"]
        })

    except Exception:
        app.logger.exception("Could not delete account")
        return jsonify({
            "error": "Database operation failed"
        }), 500
@app.route("/api/demo/accounts/<account_number>", methods=["GET"])
def get_demo_account(account_number):
    if not re.fullmatch(r"[0-9]{7}", account_number):
        return jsonify({"error": "Invalid demo account number"}), 400

    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT username, account_number, balance, is_blocked
                    FROM demo_accounts
                    WHERE account_number = %s
                    LIMIT 1
                """, (account_number,))
                row = cur.fetchone()

        if row is None:
            return jsonify({"type": "demo", "found": False}), 404

        row["balance"] = str(row["balance"])
        return jsonify({
            "type": "demo",
            "found": True,
            "account": row
        })

    except Exception:
        app.logger.exception("Demo account lookup failed")
        return jsonify({"error": "Demo account lookup failed"}), 500
