import os
from decimal import Decimal, InvalidOperation

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")


def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS demo_accounts (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    account_number TEXT NOT NULL UNIQUE,
                    balance NUMERIC(14, 2) NOT NULL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)


@app.route("/")
def home():
    return send_from_directory(".", "admin.html")


@app.route("/api/status")
def status():
    return jsonify({
        "status": "success",
        "message": "BOKKA FOX Admin API is running"
    })


@app.route("/api/accounts", methods=["GET"])
def list_accounts():
    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, account_number, balance, created_at
                    FROM demo_accounts ORDER BY id DESC
                """)
                rows = cur.fetchall()
        for row in rows:
            row["balance"] = str(row["balance"])
            row["created_at"] = row["created_at"].isoformat()
        return jsonify(rows)
    except Exception:
        app.logger.exception("Could not list demo accounts")
        return jsonify({"error": "Database operation failed"}), 500


@app.route("/api/accounts", methods=["POST"])
def add_account():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    account_number = str(data.get("account_number", "")).strip()

    if not username or not account_number:
        return jsonify({
            "error": "Username and account number are required"
        }), 400

    try:
        balance = Decimal(str(data.get("balance", "0")))
        if not balance.is_finite() or balance < 0:
            raise InvalidOperation
    except (InvalidOperation, ValueError):
        return jsonify({"error": "Invalid balance"}), 400

    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO demo_accounts
                        (username, account_number, balance)
                    VALUES (%s, %s, %s)
                    RETURNING id, username, account_number, balance
                """, (username, account_number, balance))
                row = cur.fetchone()
        row["balance"] = str(row["balance"])
        return jsonify(row), 201
    except psycopg2.errors.UniqueViolation:
        return jsonify({
            "error": "Username or account number already exists"
        }), 409
    except Exception:
        app.logger.exception("Could not add demo account")
        return jsonify({"error": "Database operation failed"}), 500


@app.route("/api/accounts/<int:account_id>/balance", methods=["PATCH"])
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
        app.logger.exception("Could not update demo balance")
        return jsonify({"error": "Database operation failed"}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
