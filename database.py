"""
Database layer for the MotoTrack Motor Shop Accessories Management System.
Uses SQLite so the whole app runs with zero external database setup.
"""
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash

DB_PATH = "motorshop.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','user')),
    can_manage_inventory INTEGER NOT NULL DEFAULT 1,
    can_manage_sales INTEGER NOT NULL DEFAULT 1,
    can_view_reports INTEGER NOT NULL DEFAULT 1,
    can_manage_users INTEGER NOT NULL DEFAULT 0,
    can_manage_purchasing INTEGER NOT NULL DEFAULT 1,
    is_active INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    created_by INTEGER
);

CREATE TABLE IF NOT EXISTS inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sku TEXT UNIQUE NOT NULL,
    item_name TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'General',
    brand TEXT,
    cost_price REAL NOT NULL DEFAULT 0,
    selling_price REAL NOT NULL DEFAULT 0,
    quantity INTEGER NOT NULL DEFAULT 0,
    unit TEXT NOT NULL DEFAULT 'pcs',
    low_stock_threshold INTEGER NOT NULL DEFAULT 5,
    date_added TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    added_by INTEGER,
    barcode TEXT,
    size TEXT,
    version TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(added_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS stock_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    change_qty INTEGER NOT NULL,
    reason TEXT NOT NULL,
    note TEXT,
    log_date TEXT NOT NULL,
    by_user INTEGER,
    FOREIGN KEY(item_id) REFERENCES inventory(id),
    FOREIGN KEY(by_user) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_no TEXT UNIQUE NOT NULL,
    sale_date TEXT NOT NULL,
    sale_datetime TEXT NOT NULL,
    buyer_name TEXT NOT NULL,
    buyer_contact TEXT,
    subtotal REAL NOT NULL,
    discount_percent REAL NOT NULL DEFAULT 0,
    discount_amount REAL NOT NULL DEFAULT 0,
    total REAL NOT NULL,
    payment_method TEXT NOT NULL DEFAULT 'Cash',
    cashier_id INTEGER,
    cash_received REAL,
    change_amount REAL,
    branch TEXT NOT NULL DEFAULT 'Main',
    imported_from_file INTEGER NOT NULL DEFAULT 0,
    external_ref TEXT UNIQUE,
    FOREIGN KEY(cashier_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS sale_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_id INTEGER NOT NULL,
    item_id INTEGER,
    item_name TEXT NOT NULL,
    unit_price REAL NOT NULL,
    unit_cost REAL NOT NULL DEFAULT 0,
    quantity INTEGER NOT NULL,
    line_subtotal REAL NOT NULL,
    FOREIGN KEY(sale_id) REFERENCES sales(id),
    FOREIGN KEY(item_id) REFERENCES inventory(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    details TEXT NOT NULL,
    performed_by INTEGER,
    performed_by_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(performed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS suppliers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    contact_person TEXT,
    phone TEXT,
    email TEXT,
    address TEXT,
    notes TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS purchase_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    po_number TEXT UNIQUE NOT NULL,
    supplier_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','partial','received','cancelled')),
    order_date TEXT NOT NULL,
    received_date TEXT,
    notes TEXT,
    total_cost REAL NOT NULL DEFAULT 0,
    created_by INTEGER,
    FOREIGN KEY(supplier_id) REFERENCES suppliers(id),
    FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS purchase_order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    po_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    item_name TEXT NOT NULL,
    quantity_ordered INTEGER NOT NULL,
    quantity_received INTEGER NOT NULL DEFAULT 0,
    unit_cost REAL NOT NULL,
    line_total REAL NOT NULL,
    FOREIGN KEY(po_id) REFERENCES purchase_orders(id),
    FOREIGN KEY(item_id) REFERENCES inventory(id)
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS processed_transfers (
    transfer_id TEXT PRIMARY KEY,
    source_branch TEXT NOT NULL,
    processed_at TEXT NOT NULL
);
"""


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()

    # Migration: add barcode column for anyone running an older database
    # that was created before this feature existed.
    existing_cols = [row["name"] for row in conn.execute("PRAGMA table_info(inventory)")]
    if "barcode" not in existing_cols:
        conn.execute("ALTER TABLE inventory ADD COLUMN barcode TEXT")
        conn.commit()
    if "is_active" not in existing_cols:
        conn.execute("ALTER TABLE inventory ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
        conn.commit()
    if "size" not in existing_cols:
        conn.execute("ALTER TABLE inventory ADD COLUMN size TEXT")
        conn.commit()
    if "version" not in existing_cols:
        conn.execute("ALTER TABLE inventory ADD COLUMN version TEXT")
        conn.commit()

    sales_cols = [row["name"] for row in conn.execute("PRAGMA table_info(sales)")]
    if "cash_received" not in sales_cols:
        conn.execute("ALTER TABLE sales ADD COLUMN cash_received REAL")
        conn.commit()
    if "change_amount" not in sales_cols:
        conn.execute("ALTER TABLE sales ADD COLUMN change_amount REAL")
        conn.commit()
    if "branch" not in sales_cols:
        conn.execute("ALTER TABLE sales ADD COLUMN branch TEXT NOT NULL DEFAULT 'Main'")
        conn.commit()
    if "imported_from_file" not in sales_cols:
        conn.execute("ALTER TABLE sales ADD COLUMN imported_from_file INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    if "external_ref" not in sales_cols:
        conn.execute("ALTER TABLE sales ADD COLUMN external_ref TEXT")
        conn.commit()
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sales_external_ref ON sales(external_ref)")
    conn.commit()

    sale_items_cols = [row["name"] for row in conn.execute("PRAGMA table_info(sale_items)")]
    if "unit_cost" not in sale_items_cols:
        conn.execute("ALTER TABLE sale_items ADD COLUMN unit_cost REAL NOT NULL DEFAULT 0")
        conn.commit()

    users_cols = [row["name"] for row in conn.execute("PRAGMA table_info(users)")]
    if "can_manage_purchasing" not in users_cols:
        conn.execute("ALTER TABLE users ADD COLUMN can_manage_purchasing INTEGER NOT NULL DEFAULT 1")
        conn.commit()
    if "failed_attempts" not in users_cols:
        conn.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    if "locked_until" not in users_cols:
        conn.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
        conn.commit()

    existing = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if existing == 0:
        conn.execute(
            """INSERT INTO users
               (username, password_hash, full_name, role,
                can_manage_inventory, can_manage_sales, can_view_reports, can_manage_users,
                is_active, created_at, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "admin",
                generate_password_hash("admin123"),
                "Shop Administrator",
                "admin",
                1, 1, 1, 1,
                1,
                datetime.now().isoformat(timespec="seconds"),
                None,
            ),
        )
        conn.commit()

    # Seed a default branch name (this install's shop location label) if not set yet
    existing_branch = conn.execute("SELECT value FROM app_settings WHERE key='branch_name'").fetchone()
    if existing_branch is None:
        conn.execute("INSERT INTO app_settings (key, value) VALUES ('branch_name', 'Main')")
        conn.commit()

    conn.close()


def get_branch_name():
    conn = get_db()
    row = conn.execute("SELECT value FROM app_settings WHERE key='branch_name'").fetchone()
    conn.close()
    return row["value"] if row else "Main"


def set_branch_name(name):
    conn = get_db()
    conn.execute(
        "INSERT INTO app_settings (key, value) VALUES ('branch_name', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (name,),
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized:", DB_PATH)
