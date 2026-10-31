
import os
import re
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")
SESSION_HOURS = int(os.environ.get("SESSION_HOURS", "24"))


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
                    password_hash TEXT,
                    is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                ALTER TABLE demo_accounts
                ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN NOT NULL DEFAULT FALSE
            """)
            cur.execute("""
                ALTER TABLE demo_accounts
                ADD COLUMN IF NOT EXISTS password_hash TEXT
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS saved_accounts (
                    id SERIAL PRIMARY KEY,
                    full_account_number TEXT NOT NULL,
                    short_account_number TEXT NOT NULL,
                    owner_name TEXT NOT NULL,
                    account_type TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS demo_sessions (
                    id SERIAL PRIMARY KEY,
                    account_id INTEGER NOT NULL REFERENCES demo_accounts(id)
                        ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE,
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS demo_transfers (
                    id SERIAL PRIMARY KEY,
                    transaction_id TEXT NOT NULL UNIQUE,
                    client_trx_id TEXT NOT NULL UNIQUE,
                    sender_account TEXT NOT NULL,
                    recipient_short_number TEXT NOT NULL,
                    recipient_name TEXT NOT NULL,
                    amount NUMERIC(14, 2) NOT NULL CHECK (amount > 0),
                    comment TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)


def request_data():
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        return data
    return request.form.to_dict()


def authorized():
    supplied = request.headers.get("Authorization", "")
    return bool(ADMIN_TOKEN) and secrets.compare_digest(
        supplied, f"Bearer {ADMIN_TOKEN}"
    )


@app.before_request
def protect_admin_operations():
    if request.path.startswith("/api/admin/") and not authorized():
        return jsonify({"error": "Unauthorized"}), 401


@app.route("/")
def home():
    return send_from_directory(".", "admin.html")


@app.route("/dushka-entry")
def dushka_entry_page():
    return send_from_directory(".", "dushka-entry.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/status")
def status():
    return jsonify({
        "status": "success",
        "message": "BOKKA FOX API is running",
        "mode": "simulation"
    })


@app.route("/api/accounts", methods=["GET"])
def list_accounts():
    if not authorized():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, account_number, balance,
                           is_blocked, created_at
                    FROM demo_accounts ORDER BY id DESC
                """)
                rows = cur.fetchall()
        for row in rows:
            row["balance"] = str(row["balance"])
            row["created_at"] = row["created_at"].isoformat()
        return jsonify(rows)
    except Exception:
        app.logger.exception("Could not list accounts")
        return jsonify({"error": "Database operation failed"}), 500


@app.route("/api/admin/accounts", methods=["POST"])
def add_account():
    data = request_data()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    if not username:
        return jsonify({"error": "أدخل اسم المستخدم"}), 400
    if len(password) < 6:
        return jsonify({"error": "كلمة المرور يجب أن تكون 6 أحرف على الأقل"}), 400
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
                account_number = None
                for _ in range(50):
                    candidate = str(secrets.randbelow(9000000) + 1000000)
                    cur.execute(
                        "SELECT 1 FROM demo_accounts WHERE account_number = %s",
                        (candidate,)
                    )
                    if cur.fetchone() is None:
                        account_number = candidate
                        break
                if account_number is None:
                    return jsonify({"error": "تعذر توليد رقم حساب، حاول مرة أخرى"}), 503
                cur.execute("""
                    INSERT INTO demo_accounts
                    (username, account_number, balance, password_hash)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, username, account_number, balance, is_blocked
                """, (username, account_number, balance,
                      generate_password_hash(password)))
                row = cur.fetchone()
        row["balance"] = str(row["balance"])
        return jsonify(row), 201
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "اسم المستخدم موجود مسبقاً"}), 409
    except Exception:
        app.logger.exception("Could not add account")
        return jsonify({"error": "Database operation failed"}), 500


@app.route("/api/demo/login", methods=["POST"])
def demo_login():
    data = request_data()
    account_number = str(data.get("account_number", "")).strip()
    password = str(data.get("password", ""))
    if not re.fullmatch(r"[0-9]{7}", account_number) or not password:
        return jsonify({"success": False, "message": "بيانات الدخول غير صحيحة"}), 400
    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, account_number, balance,
                           is_blocked, password_hash
                    FROM demo_accounts WHERE account_number = %s LIMIT 1
                """, (account_number,))
                row = cur.fetchone()
                if (row is None or row["is_blocked"] or not row["password_hash"]
                        or not check_password_hash(row["password_hash"], password)):
                    return jsonify({
                        "success": False,
                        "message": "رقم الحساب أو كلمة المرور غير صحيحة"
                    }), 401

                raw_token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
                expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=SESSION_HOURS)
                cur.execute("""
                    INSERT INTO demo_sessions (account_id, token_hash, expires_at)
                    VALUES (%s, %s, %s)
                """, (row["id"], token_hash, expires_at))

        return jsonify({
            "success": True,
            "username": row["username"],
            "account_number": row["account_number"],
            "balance": float(row["balance"]),
            "session_token": raw_token,
            "expires_in": SESSION_HOURS * 3600,
            "mode": "simulation"
        })
    except Exception:
        app.logger.exception("Demo login failed")
        return jsonify({"success": False, "message": "Login service unavailable"}), 500


def get_session_account(cur):
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.startswith("Bearer ") else ""
    if not token:
        data = request_data()
        token = str(data.get("session_token", "")).strip()
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    cur.execute("""
        SELECT a.id, a.account_number, a.balance, a.is_blocked
        FROM demo_sessions s
        JOIN demo_accounts a ON a.id = s.account_id
        WHERE s.token_hash = %s AND s.expires_at > CURRENT_TIMESTAMP
        LIMIT 1
    """, (token_hash,))
    row = cur.fetchone()
    if row is None or row["is_blocked"]:
        return None
    return row
@app.route("/api/demo/logout", methods=["POST"])
def demo_logout():
    data = request_data()
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.startswith("Bearer ") else str(data.get("session_token", "")).strip()
    if not token:
        return jsonify({"success": False, "message": "Session required"}), 401
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM demo_sessions WHERE token_hash = %s", (token_hash,))
        return jsonify({"success": True})
    except Exception:
        app.logger.exception("Logout failed")
        return jsonify({"success": False, "message": "Logout failed"}), 500


@app.route("/api/update_balance.php", methods=["POST"])
def demo_transfer():
    data = request_data()
    try:
        amount = Decimal(str(data.get("transfer_amount", "")))
        if not amount.is_finite() or amount <= 0 or amount > Decimal("1000000000"):
            raise InvalidOperation
        amount = amount.quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        return jsonify({"success": False, "message": "مبلغ التحويل غير صحيح"}), 400

    client_trx_id = str(data.get("client_trx_id", "")).strip()
    recipient = str(data.get("target_account_identifier_for_server", "")).strip()
    comment = str(data.get("comment", "")).strip()[:250]
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,100}", client_trx_id):
        return jsonify({"success": False, "message": "رقم العملية غير صحيح"}), 400
    if not re.fullmatch(r"[0-9]{7}", recipient):
        return jsonify({"success": False, "message": "رقم المستفيد غير صحيح"}), 400

    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                sender = get_session_account(cur)
                if sender is None:
                    return jsonify({
                        "success": False,
                        "message": "انتهت الجلسة أو يلزم تسجيل الدخول مجدداً"
                    }), 401

                cur.execute("""
                    SELECT transaction_id, amount
                    FROM demo_transfers WHERE client_trx_id = %s
                """, (client_trx_id,))
                duplicate = cur.fetchone()
                if duplicate:
                    return jsonify({
                        "success": False,
                        "message": "تم استلام هذه العملية مسبقاً",
                        "transaction_id": duplicate["transaction_id"]
                    }), 409

                cur.execute("""
                    SELECT short_account_number, owner_name
                    FROM saved_accounts
                    WHERE short_account_number = %s
                    ORDER BY id DESC LIMIT 1
                """, (recipient,))
                beneficiary = cur.fetchone()
                if beneficiary is None:
                    return jsonify({"success": False, "message": "حساب المستفيد غير موجود"}), 404

                cur.execute("""
                    SELECT balance, is_blocked FROM demo_accounts
                    WHERE id = %s FOR UPDATE
                """, (sender["id"],))
                locked_sender = cur.fetchone()
                if locked_sender is None or locked_sender["is_blocked"]:
                    return jsonify({"success": False, "message": "الحساب غير متاح"}), 403
                if Decimal(locked_sender["balance"]) < amount:
                    return jsonify({"success": False, "message": "الرصيد غير كافٍ"}), 400

                cur.execute("""
                    UPDATE demo_accounts SET balance = balance - %s
                    WHERE id = %s RETURNING balance
                """, (amount, sender["id"]))
                new_balance = cur.fetchone()["balance"]

                transaction_id = "DEMO-" + secrets.token_hex(8).upper()
                cur.execute("""
                    INSERT INTO demo_transfers
                    (transaction_id, client_trx_id, sender_account,
                     recipient_short_number, recipient_name, amount, comment)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (transaction_id, client_trx_id, sender["account_number"],
                      recipient, beneficiary["owner_name"], amount, comment))

        return jsonify({
            "success": True,
            "mode": "simulation",
            "message": "تم تسجيل التحويل التجريبي بنجاح",
            "transaction_id": transaction_id,
            "new_balance": float(new_balance)
        })
    except psycopg2.errors.UniqueViolation:
        return jsonify({"success": False, "message": "العملية مسجلة مسبقاً"}), 409
    except Exception:
        app.logger.exception("Demo transfer failed")
        return jsonify({"success": False, "message": "تعذر تنفيذ التحويل التجريبي"}), 500


@app.route("/api/admin/transfers", methods=["GET"])
def admin_transfers():
    if not authorized():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, transaction_id, client_trx_id, sender_account,
                           recipient_short_number, recipient_name, amount,
                           comment, created_at
                    FROM demo_transfers ORDER BY id DESC LIMIT 500
                """)
                rows = cur.fetchall()
        for row in rows:
            row["amount"] = str(row["amount"])
            row["created_at"] = row["created_at"].isoformat()
        return jsonify({"mode": "simulation", "transfers": rows})
    except Exception:
        app.logger.exception("Could not list transfers")
        return jsonify({"error": "Database operation failed"}), 500


@app.route("/api/admin/accounts/<int:account_id>/balance", methods=["PATCH"])
def update_balance(account_id):
    data = request_data()
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
                    UPDATE demo_accounts SET balance = %s WHERE id = %s
                    RETURNING id, username, account_number, balance
                """, (balance, account_id))
                row = cur.fetchone()
        if row is None:
            return jsonify({"error": "Account not found"}), 404
        row["balance"] = str(row["balance"])
        return jsonify(row)
    except Exception:
        app.logger.exception("Could not update balance")
        return jsonify({"error": "Database operation failed"}), 500


@app.route("/api/admin/accounts/<int:account_id>/block", methods=["PATCH"])
def block_account(account_id):
    data = request_data()
    blocked = data.get("blocked")
    if not isinstance(blocked, bool):
        return jsonify({"error": "blocked must be true or false"}), 400
    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE demo_accounts SET is_blocked = %s WHERE id = %s
                    RETURNING id, username, is_blocked
                """, (blocked, account_id))
                row = cur.fetchone()
        if row is None:
            return jsonify({"error": "Account not found"}), 404
        return jsonify(row)
    except Exception:
        app.logger.exception("Could not change block status")
        return jsonify({"error": "Database operation failed"}), 500


@app.route("/api/admin/accounts/<int:account_id>", methods=["DELETE"])
def delete_account(account_id):
    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM demo_accounts WHERE id = %s RETURNING id
                """, (account_id,))
                row = cur.fetchone()
        if row is None:
            return jsonify({"error": "Account not found"}), 404
        return jsonify({"status": "success", "deleted_id": row["id"]})
    except Exception:
        app.logger.exception("Could not delete account")
        return jsonify({"error": "Database operation failed"}), 500


@app.route("/api/fetch_balance.php", methods=["POST"])
def fetch_demo_balance():
    data = request_data()
    account_number = str(data.get("account_number", "")).strip()
    if not re.fullmatch(r"[0-9]{7}", account_number):
        return jsonify({"success": False, "balance": 0})
    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT balance, is_blocked FROM demo_accounts
                    WHERE account_number = %s LIMIT 1
                """, (account_number,))
                row = cur.fetchone()
        if row is None or row["is_blocked"]:
            return jsonify({"success": False, "balance": 0})
        return jsonify({"success": True, "balance": float(row["balance"])})
    except Exception:
        app.logger.exception("Demo balance lookup failed")
        return jsonify({"success": False, "balance": 0}), 500


@app.route("/api/saved-accounts", methods=["POST"])
def public_add_saved_account():
    data = request_data()
    translation = str.maketrans(
        "٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789"
    )
    full_number = str(data.get("full_account_number", "")).strip().translate(translation)
    owner_name = str(data.get("owner_name", "")).strip()
    account_type = str(data.get("account_type", "")).strip()
    branch = str(data.get("branch", "")).strip()
    if not re.fullmatch(r"[0-9]{16}", full_number):
        return jsonify({"error": "رقم الحساب يجب أن يتكون من 16 رقماً"}), 400
    if not all([owner_name, account_type, branch]):
        return jsonify({"error": "يرجى إكمال جميع الحقول"}), 400
    short_number = full_number[5:12]
    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO saved_accounts
                    (full_account_number, short_account_number, owner_name, account_type, branch)
                    VALUES (%s, %s, %s, %s, %s) RETURNING id
                """, (full_number, short_number, owner_name, account_type, branch))
                row = cur.fetchone()
        return jsonify({
            "success": True, "message": "تم حفظ البيانات بنجاح",
            "id": row["id"], "short_account_number": short_number
        }), 201
    except Exception:
        app.logger.exception("Could not save public Dushka account")
        return jsonify({"error": "تعذر حفظ البيانات، حاول مرة أخرى"}), 500


@app.route("/api/check_internal_account_2.php", methods=["POST"])
def check_internal_account():
    data = request_data()
    translation = str.maketrans(
        "٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789"
    )
    short_number = str(
        data.get("short_account_number", data.get("account_number", ""))
    ).strip().translate(translation)
    if not re.fullmatch(r"[0-9]{7}", short_number):
        return jsonify({
            "success": False, "found": False, "message": "رقم الحساب غير صحيح"
        }), 400
    try:
        init_db()
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT short_account_number, owner_name, account_type, branch
                    FROM saved_accounts
                    WHERE short_account_number = %s
                    ORDER BY id DESC LIMIT 1
                """, (short_number,))
                row = cur.fetchone()
        if row is None:
            return jsonify({"success": True, "found": False, "message": "الحساب غير موجود"})
        return jsonify({
            "success": True, "found": True,
            "account_number": row["short_account_number"],
            "owner_name": row["owner_name"],
            "account_type": row["account_type"],
            "branch": row["branch"]
        })
    except Exception:
        app.logger.exception("Dushka account lookup failed")
        return jsonify({
            "success": False, "found": False, "message": "حدث خطأ أثناء البحث"
        }), 500


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)