import os
import re
import secrets
from decimal import Decimal, InvalidOperation

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

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

            # جدول الحسابات التجريبية القديم
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
                ADD COLUMN IF NOT EXISTS
                is_blocked BOOLEAN NOT NULL DEFAULT FALSE
            """)

            cur.execute("""
                ALTER TABLE demo_accounts
                ADD COLUMN IF NOT EXISTS password_hash TEXT
            """)

            # جدول مستقل لحفظ السجلات التجريبية المصرح بها
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


def request_data():
    """قراءة البيانات بصيغة JSON أو Form."""
    data = request.get_json(silent=True)

    if isinstance(data, dict):
        return data

    return request.form.to_dict()


def authorized():
    supplied = request.headers.get("Authorization", "")
    return bool(ADMIN_TOKEN) and supplied == f"Bearer {ADMIN_TOKEN}"


@app.before_request
def protect_admin_operations():
    if request.path.startswith("/api/admin/") and not authorized():
        return jsonify({"error": "Unauthorized"}), 401
@app.route("/")
def home():
    return send_from_directory(".", "admin.html")


@app.route("/admin/saved-accounts")
def saved_accounts_page():
    return send_from_directory(".", "saved-accounts.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/status")
def status():
    return jsonify({
        "status": "success",
        "message": "BOKKA FOX API is running"
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

    data = request_data()

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username:
        return jsonify({
            "error": "أدخل اسم المستخدم"
        }), 400

    if len(password) < 6:
        return jsonify({
            "error": "كلمة المرور يجب أن تكون 6 أحرف على الأقل"
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

                account_number = None

                for _ in range(50):
                    candidate = str(
                        secrets.randbelow(9000000) + 1000000
                    )

                    cur.execute("""
                        SELECT 1 FROM demo_accounts
                        WHERE account_number = %s
                    """, (candidate,))

                    if cur.fetchone() is None:
                        account_number = candidate
                        break

                if account_number is None:
                    return jsonify({
                        "error": "تعذر توليد رقم حساب، حاول مرة أخرى"
                    }), 503

                cur.execute("""
                    INSERT INTO demo_accounts
                    (username, account_number, balance, password_hash)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, username, account_number,
                              balance, is_blocked
                """, (
                    username,
                    account_number,
                    balance,
                    generate_password_hash(password)
                ))

                row = cur.fetchone()

        row["balance"] = str(row["balance"])

        return jsonify(row), 201

    except psycopg2.errors.UniqueViolation:
        return jsonify({
            "error": "اسم المستخدم موجود مسبقاً"
        }), 409

    except Exception:
        app.logger.exception("Could not add account")
        return jsonify({
            "error": "Database operation failed"
        }), 500
@app.route("/api/demo/login", methods=["POST"])
def demo_login():

    data = request_data()

    account_number = str(
        data.get("account_number", "")
    ).strip()

    password = str(data.get("password", ""))

    if not re.fullmatch(r"[0-9]{7}", account_number) or not password:
        return jsonify({
            "success": False,
            "message": "بيانات الدخول غير صحيحة"
        }), 400

    try:
        init_db()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT username, account_number,
                           balance, is_blocked, password_hash
                    FROM demo_accounts
                    WHERE account_number = %s
                    LIMIT 1
                """, (account_number,))

                row = cur.fetchone()

        if (
            row is None
            or row["is_blocked"]
            or not row["password_hash"]
            or not check_password_hash(
                row["password_hash"], password
            )
        ):
            return jsonify({
                "success": False,
                "message": "رقم الحساب أو كلمة المرور غير صحيحة"
            }), 401

        return jsonify({
            "success": True,
            "username": row["username"],
            "account_number": row["account_number"],
            "balance": float(row["balance"])
        })

    except Exception:
        app.logger.exception("Demo login failed")
        return jsonify({
            "success": False,
            "message": "Login service unavailable"
        }), 500


@app.route(
    "/api/admin/accounts/<int:account_id>/balance",
    methods=["PATCH"]
)
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
                    UPDATE demo_accounts
                    SET balance = %s
                    WHERE id = %s
                    RETURNING id, username, account_number, balance
                """, (balance, account_id))

                row = cur.fetchone()

        if row is None:
            return jsonify({
                "error": "Account not found"
            }), 404

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

    data = request_data()
    is_blocked = data.get("is_blocked")

    if not isinstance(is_blocked, bool):
        return jsonify({
            "error": "قيمة الحظر غير صحيحة"
        }), 400

    try:
        init_db()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE demo_accounts
                    SET is_blocked = %s
                    WHERE id = %s
                    RETURNING id, username, account_number,
                              is_blocked
                """, (is_blocked, account_id))

                row = cur.fetchone()

        if row is None:
            return jsonify({
                "error": "Account not found"
            }), 404

        return jsonify(row)

    except Exception:
        app.logger.exception("Could not update account block")
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
            return jsonify({
                "error": "Account not found"
            }), 404

        return jsonify({
            "success": True,
            "message": "Account deleted"
        })

    except Exception:
        app.logger.exception("Could not delete account")
        return jsonify({
            "error": "Database operation failed"
        }), 500


@app.route("/api/fetch_balance.php", methods=["POST"])
def fetch_balance():

    data = request_data()

    account_number = str(
        data.get("account_number", "")
    ).strip()

    if not re.fullmatch(r"[0-9]{7}", account_number):
        return jsonify({
            "success": False,
            "message": "رقم الحساب غير صحيح"
        }), 400

    try:
        init_db()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT username, account_number,
                           balance, is_blocked
                    FROM demo_accounts
                    WHERE account_number = %s
                    LIMIT 1
                """, (account_number,))

                row = cur.fetchone()

        if row is None or row["is_blocked"]:
            return jsonify({
                "success": False,
                "message": "الحساب غير متاح"
            }), 404

        return jsonify({
            "success": True,
            "username": row["username"],
            "account_number": row["account_number"],
            "balance": float(row["balance"])
        })

    except Exception:
        app.logger.exception("Could not fetch balance")
        return jsonify({
            "success": False,
            "message": "Service unavailable"
        }), 500


@app.route("/api/admin/saved-accounts", methods=["POST"])
def add_saved_account():

    data = request_data()

    full_number = str(
        data.get("full_account_number", "")
    ).strip()

    short_number = str(
        data.get("short_account_number", "")
    ).strip()

    owner_name = str(
        data.get("owner_name", "")
    ).strip()

    account_type = str(
        data.get("account_type", "")
    ).strip()

    branch = str(
        data.get("branch", "")
    ).strip()

    if not re.fullmatch(r"[0-9]{16}", full_number):
        return jsonify({
            "error": "رقم الحساب الكامل يجب أن يتكون من 16 رقماً"
        }), 400

    if not re.fullmatch(r"[0-9]{7}", short_number):
        return jsonify({
            "error": "الرقم المختصر يجب أن يتكون من 7 أرقام"
        }), 400

    if not all([
        owner_name,
        account_type,
        branch
    ]):
        return jsonify({
            "error": "يرجى إكمال جميع الحقول"
        }), 400

    try:
        init_db()

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO saved_accounts (
                        full_account_number,
                        short_account_number,
                        owner_name,
                        account_type,
                        branch
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id, short_account_number,
                              owner_name, account_type,
                              branch, created_at
                """, (
                    full_number,
                    short_number,
                    owner_name,
                    account_type,
                    branch
                ))

                row = cur.fetchone()

        row["created_at"] = row["created_at"].isoformat()

        return jsonify({
            "success": True,
            "message": "تم حفظ البيانات بنجاح",
            "account": row
        }), 201

    except Exception:
        app.logger.exception("Could not save account")
        return jsonify({
            "error": "تعذر حفظ البيانات"
        }), 500
if __name__ == "__main__":
    init_db()

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )