"""
MotoTrack — Motor Shop Accessories Management System
------------------------------------------------------
Features:
  - Login system with Admin / User roles
  - Admin can create more admin/user accounts and assign per-user access restrictions
  - Inventory management: adding stock for an existing item auto-increments quantity
  - Point-of-sale with buyer discount (flat peso amount), automatic total computation,
    printable receipt
  - Purchase / sales history filterable by date and month

Run with:  python app.py   (or double-click start.bat on Windows)
Default login:  admin / admin123   (change the password after first login)
"""
import os
import functools
import secrets
import json
from io import BytesIO
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, g, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from database import get_db, init_db, DB_PATH, get_branch_name, set_branch_name

app = Flask(__name__)


def get_or_create_secret_key():
    """Uses MOTORSHOP_SECRET if set (e.g. for a shared VPS deployment).
    Otherwise generates a strong random key once and saves it locally, so
    login sessions stay secure without needing any manual setup."""
    if os.environ.get("MOTORSHOP_SECRET"):
        return os.environ["MOTORSHOP_SECRET"]
    key_file = "secret_key.txt"
    if os.path.exists(key_file):
        with open(key_file, "r") as f:
            return f.read().strip()
    new_key = secrets.token_hex(32)
    with open(key_file, "w") as f:
        f.write(new_key)
    return new_key


app.secret_key = get_or_create_secret_key()

LOGIN_LOCKOUT_THRESHOLD = 5
LOGIN_LOCKOUT_MINUTES = 15


# ---------------------------------------------------------------------------
# Helpers / decorators
# ---------------------------------------------------------------------------
def current_user():
    if "user_id" not in session:
        return None
    if "_user_cache" not in g:
        db = get_db()
        g._user_cache = db.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        db.close()
    return g._user_cache


@app.context_processor
def inject_user():
    return {"current_user": current_user(), "branch_name": get_branch_name()}


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def permission_required(flag):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if user is None:
                return redirect(url_for("login"))
            if user["role"] != "admin" and not user[flag]:
                flash("You don't have access to that section. Ask an admin for access.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "admin":
            flash("Admin access only.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def next_sku(db):
    row = db.execute("SELECT COUNT(*) AS c FROM inventory").fetchone()
    return f"SKU-{row['c'] + 1:05d}"


def next_receipt_no(db):
    row = db.execute("SELECT COUNT(*) AS c FROM sales").fetchone()
    today = datetime.now().strftime("%Y%m%d")
    return f"R-{today}-{row['c'] + 1:04d}"


def next_po_number(db):
    row = db.execute("SELECT COUNT(*) AS c FROM purchase_orders").fetchone()
    return f"PO-{row['c'] + 1:05d}"


def log_audit(db, action, details):
    """Records who did what, for accountability. performed_by_name is
    stored as a snapshot so the log stays readable even if an account is
    later deactivated."""
    user = current_user()
    db.execute(
        """INSERT INTO audit_log (action, details, performed_by, performed_by_name, created_at)
           VALUES (?,?,?,?,?)""",
        (action, details, user["id"] if user else None,
         user["full_name"] if user else "Unknown",
         datetime.now().isoformat(timespec="seconds")),
    )


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        now = datetime.now()
        locked = False
        if user and user["locked_until"]:
            locked_until_dt = datetime.fromisoformat(user["locked_until"])
            if now < locked_until_dt:
                locked = True
                minutes_left = int((locked_until_dt - now).total_seconds() / 60) + 1
                flash(f"Too many failed login attempts. This account is locked for about "
                      f"{minutes_left} more minute(s). Please try again later.", "error")

        if not locked:
            if user is None or not check_password_hash(user["password_hash"], password):
                if user is not None:
                    new_attempts = user["failed_attempts"] + 1
                    lock_until = None
                    if new_attempts >= LOGIN_LOCKOUT_THRESHOLD:
                        lock_until = (now + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)).isoformat(timespec="seconds")
                        db.execute("UPDATE users SET failed_attempts=0, locked_until=? WHERE id=?",
                                   (lock_until, user["id"]))
                        log_audit(db, "Account Locked",
                                  f"'{user['username']}' locked for {LOGIN_LOCKOUT_MINUTES} minutes after {LOGIN_LOCKOUT_THRESHOLD} failed login attempts")
                        db.commit()
                        flash(f"Too many failed attempts. This account is now locked for {LOGIN_LOCKOUT_MINUTES} minutes.", "error")
                    else:
                        db.execute("UPDATE users SET failed_attempts=? WHERE id=?", (new_attempts, user["id"]))
                        db.commit()
                        flash("Incorrect username or password.", "error")
                else:
                    flash("Incorrect username or password.", "error")
            elif not user["is_active"]:
                flash("This account has been deactivated. Contact an admin.", "error")
            else:
                db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
                db.commit()
                session.clear()
                session["user_id"] = user["id"]
                if user["username"] == "admin" and check_password_hash(user["password_hash"], "admin123"):
                    flash("Security tip: you're still using the default admin password (admin123). "
                          "Please change it from My Account.", "error")
                flash(f"Welcome back, {user['full_name']}!", "success")
                db.close()
                return redirect(url_for("dashboard"))
        db.close()
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You've been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/settings/branch", methods=["GET", "POST"])
@admin_required
def settings_branch():
    if request.method == "POST":
        name = request.form.get("branch_name", "").strip()
        if not name:
            flash("Branch name can't be empty.", "error")
        else:
            old_name = get_branch_name()
            set_branch_name(name)
            db = get_db()
            log_audit(db, "Branch Name Changed", f"Changed this install's branch name from '{old_name}' to '{name}'")
            db.commit()
            db.close()
            flash(f"This install is now labeled '{name}'.", "success")
            return redirect(url_for("dashboard"))
    return render_template("settings_branch.html", current_branch=get_branch_name())


# ---------------------------------------------------------------------------
# Branch Sync: Stock Transfers & Sales Export/Import
# ---------------------------------------------------------------------------
def find_or_create_local_item(db, item_data, user_id, note_suffix=""):
    """Given item details from an incoming transfer file, find a matching
    local item (by barcode, else by name+brand+size+version) or create a
    new one, then add the given quantity to it. Mirrors the same matching
    rules used in Add Stock, so transferred stock behaves identically to a
    manual restock."""
    barcode = item_data.get("barcode") or None
    size = item_data.get("size") or None
    version = item_data.get("version") or None
    qty = int(item_data.get("quantity", 0))
    now = datetime.now().isoformat(timespec="seconds")

    existing = None
    if barcode:
        existing = db.execute("SELECT * FROM inventory WHERE barcode = ?", (barcode,)).fetchone()
    if existing is None:
        existing = db.execute(
            """SELECT * FROM inventory WHERE item_name = ? AND IFNULL(brand,'') = IFNULL(?,'')
               AND IFNULL(size,'') = IFNULL(?,'') AND IFNULL(version,'') = IFNULL(?,'')""",
            (item_data.get("item_name", ""), item_data.get("brand"), size, version),
        ).fetchone()

    if existing:
        new_qty = existing["quantity"] + qty
        db.execute("UPDATE inventory SET quantity=?, is_active=1, last_updated=? WHERE id=?",
                   (new_qty, now, existing["id"]))
        item_id = existing["id"]
    else:
        sku = next_sku(db)
        cur = db.execute(
            """INSERT INTO inventory
               (sku, item_name, category, brand, cost_price, selling_price, quantity, unit,
                low_stock_threshold, date_added, last_updated, added_by, barcode, size, version)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (sku, item_data.get("item_name", "Unnamed Item"), item_data.get("category", "General"),
             item_data.get("brand"), item_data.get("cost_price", 0), item_data.get("selling_price", 0),
             qty, item_data.get("unit", "pcs"), 5, now, now, user_id, barcode, size, version),
        )
        item_id = cur.lastrowid

    db.execute(
        """INSERT INTO stock_log (item_id, change_qty, reason, note, log_date, by_user)
           VALUES (?,?,?,?,?,?)""",
        (item_id, qty, "transfer_in", f"Received via branch transfer{note_suffix}", now, user_id),
    )


@app.route("/inventory/transfer", methods=["GET", "POST"])
@permission_required("can_manage_inventory")
def inventory_transfer():
    db = get_db()
    if request.method == "POST":
        destination = request.form.get("destination_branch", "").strip()
        item_ids = request.form.getlist("item_id[]")
        quantities = request.form.getlist("quantity[]")

        if not destination:
            flash("Please enter the destination branch.", "error")
            db.close()
            return redirect(url_for("inventory_transfer"))

        lines = []
        error = None
        for item_id, qty_raw in zip(item_ids, quantities):
            if not item_id or not qty_raw:
                continue
            qty = int(qty_raw)
            if qty <= 0:
                continue
            item = db.execute("SELECT * FROM inventory WHERE id=?", (item_id,)).fetchone()
            if item is None:
                continue
            if qty > item["quantity"]:
                error = f"Not enough stock of '{item['item_name']}' to transfer (only {item['quantity']} available)."
                break
            lines.append({"item": item, "qty": qty})

        if error:
            flash(error, "error")
            db.close()
            return redirect(url_for("inventory_transfer"))
        if not lines:
            flash("Add at least one item with a valid quantity.", "error")
            db.close()
            return redirect(url_for("inventory_transfer"))

        now = datetime.now()
        transfer_id = f"TR-{now.strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
        transfer_items = []
        for line in lines:
            item = line["item"]
            qty = line["qty"]
            new_qty = item["quantity"] - qty
            db.execute("UPDATE inventory SET quantity=?, last_updated=? WHERE id=?",
                       (new_qty, now.isoformat(timespec="seconds"), item["id"]))
            db.execute(
                """INSERT INTO stock_log (item_id, change_qty, reason, note, log_date, by_user)
                   VALUES (?,?,?,?,?,?)""",
                (item["id"], -qty, "transfer_out", f"Transferred to {destination} ({transfer_id})",
                 now.isoformat(timespec="seconds"), session["user_id"]),
            )
            transfer_items.append({
                "barcode": item["barcode"], "sku": item["sku"], "item_name": item["item_name"],
                "category": item["category"], "brand": item["brand"], "size": item["size"],
                "version": item["version"], "cost_price": item["cost_price"],
                "selling_price": item["selling_price"], "unit": item["unit"], "quantity": qty,
            })

        payload = {
            "type": "dan_j_moto_transfer",
            "transfer_id": transfer_id,
            "source_branch": get_branch_name(),
            "destination_branch": destination,
            "transfer_date": now.isoformat(timespec="seconds"),
            "items": transfer_items,
        }
        db.commit()
        log_audit(db, "Stock Transferred Out",
                  f"{transfer_id}: sent {len(lines)} item(s) to {destination}")
        db.commit()
        db.close()

        buf = BytesIO(json.dumps(payload, indent=2).encode("utf-8"))
        filename = f"{transfer_id}-to-{destination.replace(' ', '')}.json"
        return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/json")

    items = db.execute("SELECT * FROM inventory WHERE quantity > 0 AND is_active = 1 ORDER BY item_name").fetchall()
    db.close()
    return render_template("inventory_transfer.html", items=items)


@app.route("/inventory/receive-transfer", methods=["GET", "POST"])
@permission_required("can_manage_inventory")
def inventory_receive_transfer():
    if request.method == "POST":
        uploaded = request.files.get("transfer_file")
        if not uploaded or uploaded.filename == "":
            flash("Please choose a transfer file to import.", "error")
            return redirect(url_for("inventory_receive_transfer"))

        try:
            payload = json.loads(uploaded.read().decode("utf-8"))
        except Exception:
            flash("That doesn't look like a valid transfer file.", "error")
            return redirect(url_for("inventory_receive_transfer"))

        if payload.get("type") != "dan_j_moto_transfer":
            flash("This file isn't a DAN J MOTO stock transfer file.", "error")
            return redirect(url_for("inventory_receive_transfer"))

        transfer_id = payload.get("transfer_id", "")
        db = get_db()
        already = db.execute("SELECT 1 FROM processed_transfers WHERE transfer_id=?", (transfer_id,)).fetchone()
        if already:
            db.close()
            flash(f"Transfer {transfer_id} was already received before — skipped to avoid double-counting.", "error")
            return redirect(url_for("inventory_receive_transfer"))

        source = payload.get("source_branch", "Unknown")
        note_suffix = f" from {source} ({transfer_id})"
        for item_data in payload.get("items", []):
            find_or_create_local_item(db, item_data, session["user_id"], note_suffix)

        db.execute(
            "INSERT INTO processed_transfers (transfer_id, source_branch, processed_at) VALUES (?,?,?)",
            (transfer_id, source, datetime.now().isoformat(timespec="seconds")),
        )
        db.commit()
        log_audit(db, "Stock Transfer Received",
                  f"{transfer_id}: received {len(payload.get('items', []))} item(s) from {source}")
        db.commit()
        db.close()
        flash(f"Transfer {transfer_id} from {source} received and added to stock.", "success")
        return redirect(url_for("inventory_list"))

    return render_template("inventory_receive_transfer.html")


@app.route("/reports/export-sales", methods=["GET", "POST"])
@permission_required("can_view_reports")
def export_sales():
    if request.method == "POST":
        date_from = request.form.get("date_from", "").strip()
        date_to = request.form.get("date_to", "").strip()
        if not date_from or not date_to:
            flash("Please choose both a start and end date.", "error")
            return redirect(url_for("export_sales"))

        db = get_db()
        sales = db.execute(
            """SELECT s.*, u.full_name AS cashier_name FROM sales s
               LEFT JOIN users u ON u.id = s.cashier_id
               WHERE s.sale_date BETWEEN ? AND ? AND s.imported_from_file = 0
               ORDER BY s.id""",
            (date_from, date_to),
        ).fetchall()

        export_sales_list = []
        for s in sales:
            items = db.execute("SELECT * FROM sale_items WHERE sale_id=?", (s["id"],)).fetchall()
            export_sales_list.append({
                "receipt_no": s["receipt_no"], "sale_date": s["sale_date"], "sale_datetime": s["sale_datetime"],
                "buyer_name": s["buyer_name"], "buyer_contact": s["buyer_contact"],
                "subtotal": s["subtotal"], "discount_amount": s["discount_amount"], "total": s["total"],
                "payment_method": s["payment_method"], "cashier_name": s["cashier_name"],
                "cash_received": s["cash_received"], "change_amount": s["change_amount"],
                "items": [{
                    "item_name": it["item_name"], "unit_price": it["unit_price"], "unit_cost": it["unit_cost"],
                    "quantity": it["quantity"], "line_subtotal": it["line_subtotal"],
                } for it in items],
            })

        payload = {
            "type": "dan_j_moto_sales_export",
            "branch": get_branch_name(),
            "date_from": date_from,
            "date_to": date_to,
            "exported_at": datetime.now().isoformat(timespec="seconds"),
            "sales": export_sales_list,
        }
        log_audit(db, "Sales Exported", f"Exported {len(export_sales_list)} sale(s) from {date_from} to {date_to}")
        db.commit()
        db.close()

        buf = BytesIO(json.dumps(payload, indent=2).encode("utf-8"))
        filename = f"{get_branch_name().replace(' ', '')}-sales-{date_from}-to-{date_to}.json"
        return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/json")

    return render_template("export_sales.html")


@app.route("/reports/import-branch-sales", methods=["GET", "POST"])
@admin_required
def import_branch_sales():
    if request.method == "POST":
        uploaded = request.files.get("sales_file")
        if not uploaded or uploaded.filename == "":
            flash("Please choose a sales export file to import.", "error")
            return redirect(url_for("import_branch_sales"))

        try:
            payload = json.loads(uploaded.read().decode("utf-8"))
        except Exception:
            flash("That doesn't look like a valid sales export file.", "error")
            return redirect(url_for("import_branch_sales"))

        if payload.get("type") != "dan_j_moto_sales_export":
            flash("This file isn't a DAN J MOTO sales export file.", "error")
            return redirect(url_for("import_branch_sales"))

        source_branch = payload.get("branch", "Unknown")
        db = get_db()
        imported_count = 0
        skipped_count = 0

        for sale in payload.get("sales", []):
            original_receipt = sale.get("receipt_no", "")
            external_ref = f"{source_branch}:{original_receipt}"
            exists = db.execute("SELECT 1 FROM sales WHERE external_ref=?", (external_ref,)).fetchone()
            if exists:
                skipped_count += 1
                continue

            new_receipt_no = f"{source_branch.replace(' ', '')}-{original_receipt}"
            cur = db.execute(
                """INSERT INTO sales
                   (receipt_no, sale_date, sale_datetime, buyer_name, buyer_contact, subtotal,
                    discount_percent, discount_amount, total, payment_method, cashier_id,
                    cash_received, change_amount, branch, imported_from_file, external_ref)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)""",
                (new_receipt_no, sale.get("sale_date"), sale.get("sale_datetime"),
                 sale.get("buyer_name"), sale.get("buyer_contact"), sale.get("subtotal", 0),
                 0, sale.get("discount_amount", 0), sale.get("total", 0), sale.get("payment_method", "Cash"),
                 None, sale.get("cash_received"), sale.get("change_amount"), source_branch, external_ref),
            )
            sale_id = cur.lastrowid
            for it in sale.get("items", []):
                db.execute(
                    """INSERT INTO sale_items (sale_id, item_id, item_name, unit_price, unit_cost, quantity, line_subtotal)
                       VALUES (?,?,?,?,?,?,?)""",
                    (sale_id, None, it.get("item_name"), it.get("unit_price", 0), it.get("unit_cost", 0),
                     it.get("quantity", 0), it.get("line_subtotal", 0)),
                )
            imported_count += 1

        db.commit()
        log_audit(db, "Branch Sales Imported",
                  f"Imported {imported_count} sale(s) from {source_branch} ({skipped_count} already existed, skipped)")
        db.commit()
        db.close()
        flash(f"Imported {imported_count} sale(s) from {source_branch}. "
              f"{skipped_count} were already imported before and skipped.", "success")
        return redirect(url_for("sales_history"))

    return render_template("import_branch_sales.html")


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def my_account_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        user = current_user()

        if not check_password_hash(user["password_hash"], current_password):
            flash("Your current password is incorrect.", "error")
        elif len(new_password) < 6:
            flash("New password should be at least 6 characters.", "error")
        elif new_password != confirm_password:
            flash("New password and confirmation don't match.", "error")
        else:
            db = get_db()
            db.execute("UPDATE users SET password_hash=?, failed_attempts=0, locked_until=NULL WHERE id=?",
                       (generate_password_hash(new_password), user["id"]))
            db.commit()
            log_audit(db, "Password Changed", f"'{user['username']}' changed their own password")
            db.commit()
            db.close()
            flash("Your password was updated successfully.", "success")
            return redirect(url_for("dashboard"))
    return render_template("account_password.html")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    db = get_db()
    total_items = db.execute("SELECT COUNT(*) c FROM inventory").fetchone()["c"]
    low_stock = db.execute(
        "SELECT COUNT(*) c FROM inventory WHERE quantity <= low_stock_threshold"
    ).fetchone()["c"]
    today = datetime.now().strftime("%Y-%m-%d")
    month = datetime.now().strftime("%Y-%m")
    sales_today = db.execute(
        "SELECT COALESCE(SUM(total),0) t, COUNT(*) c FROM sales WHERE sale_date = ?", (today,)
    ).fetchone()
    sales_month = db.execute(
        "SELECT COALESCE(SUM(total),0) t, COUNT(*) c FROM sales WHERE sale_date LIKE ?", (month + "%",)
    ).fetchone()
    recent_sales = db.execute(
        "SELECT * FROM sales ORDER BY id DESC LIMIT 5"
    ).fetchall()
    low_items = db.execute(
        "SELECT * FROM inventory WHERE quantity <= low_stock_threshold ORDER BY quantity ASC LIMIT 5"
    ).fetchall()
    db.close()
    return render_template(
        "dashboard.html",
        total_items=total_items,
        low_stock=low_stock,
        sales_today=sales_today,
        sales_month=sales_month,
        recent_sales=recent_sales,
        low_items=low_items,
    )


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------
@app.route("/users")
@admin_required
def users_list():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
    db.close()
    return render_template("users_list.html", users=users)


@app.route("/users/add", methods=["GET", "POST"])
@admin_required
def users_add():
    if request.method == "POST":
        username = request.form["username"].strip()
        full_name = request.form["full_name"].strip()
        password = request.form["password"]
        role = request.form["role"]
        perms = {
            "can_manage_inventory": 1 if request.form.get("can_manage_inventory") else 0,
            "can_manage_sales": 1 if request.form.get("can_manage_sales") else 0,
            "can_view_reports": 1 if request.form.get("can_view_reports") else 0,
            "can_manage_users": 1 if (role == "admin" or request.form.get("can_manage_users")) else 0,
            "can_manage_purchasing": 1 if (role == "admin" or request.form.get("can_manage_purchasing")) else 0,
        }
        db = get_db()
        exists = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            flash("That username is already taken.", "error")
        elif not username or not password or not full_name:
            flash("Please fill in all required fields.", "error")
        else:
            db.execute(
                """INSERT INTO users
                   (username, password_hash, full_name, role,
                    can_manage_inventory, can_manage_sales, can_view_reports, can_manage_users, can_manage_purchasing,
                    is_active, created_at, created_by)
                   VALUES (?,?,?,?,?,?,?,?,?,1,?,?)""",
                (
                    username, generate_password_hash(password), full_name, role,
                    perms["can_manage_inventory"], perms["can_manage_sales"],
                    perms["can_view_reports"], perms["can_manage_users"], perms["can_manage_purchasing"],
                    datetime.now().isoformat(timespec="seconds"),
                    session["user_id"],
                ),
            )
            db.commit()
            log_audit(db, "Account Created", f"Created {role} account '{username}' ({full_name})")
            db.commit()
            db.close()
            flash(f"Account '{username}' created as {role}.", "success")
            return redirect(url_for("users_list"))
        db.close()
    return render_template("users_add.html")


@app.route("/users/<int:user_id>/permissions", methods=["GET", "POST"])
@admin_required
def users_permissions(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        db.close()
        flash("Account not found.", "error")
        return redirect(url_for("users_list"))

    if request.method == "POST":
        if user_id == session["user_id"] and not request.form.get("is_active"):
            flash("You can't deactivate your own account.", "error")
        else:
            role = request.form["role"]
            can_manage_inventory = 1 if request.form.get("can_manage_inventory") else 0
            can_manage_sales = 1 if request.form.get("can_manage_sales") else 0
            can_view_reports = 1 if request.form.get("can_view_reports") else 0
            can_manage_users = 1 if (role == "admin" or request.form.get("can_manage_users")) else 0
            can_manage_purchasing = 1 if (role == "admin" or request.form.get("can_manage_purchasing")) else 0
            is_active = 1 if request.form.get("is_active") else 0
            db.execute(
                """UPDATE users SET role=?, can_manage_inventory=?, can_manage_sales=?,
                   can_view_reports=?, can_manage_users=?, can_manage_purchasing=?, is_active=? WHERE id=?""",
                (role, can_manage_inventory, can_manage_sales, can_view_reports,
                 can_manage_users, can_manage_purchasing, is_active, user_id),
            )
            db.commit()
            status_note = "active" if is_active else "DEACTIVATED"
            log_audit(db, "Access Updated",
                      f"Updated '{user['username']}' — role: {role}, status: {status_note}")
            db.commit()
            flash(f"Access updated for '{user['username']}'.", "success")
            db.close()
            return redirect(url_for("users_list"))
    db.close()
    return render_template("users_permissions.html", user=user)


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def users_reset_password(user_id):
    new_password = request.form.get("new_password", "").strip()
    if len(new_password) < 4:
        flash("Password should be at least 4 characters.", "error")
        return redirect(url_for("users_permissions", user_id=user_id))
    db = get_db()
    target_user = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    db.execute("UPDATE users SET password_hash=? WHERE id=?",
               (generate_password_hash(new_password), user_id))
    db.commit()
    log_audit(db, "Password Reset", f"Reset password for '{target_user['username']}'")
    db.commit()
    db.close()
    flash("Password reset successfully.", "success")
    return redirect(url_for("users_permissions", user_id=user_id))


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------
def get_active_inventory(db, q=""):
    if q:
        return db.execute(
            "SELECT * FROM inventory WHERE is_active = 1 AND (item_name LIKE ? OR sku LIKE ? OR category LIKE ?) ORDER BY item_name",
            (f"%{q}%", f"%{q}%", f"%{q}%"),
        ).fetchall()
    return db.execute("SELECT * FROM inventory WHERE is_active = 1 ORDER BY item_name").fetchall()


@app.route("/inventory")
@permission_required("can_manage_inventory")
def inventory_list():
    q = request.args.get("q", "").strip()
    db = get_db()
    items = get_active_inventory(db, q)
    db.close()
    return render_template("inventory_list.html", items=items, q=q)


@app.route("/inventory/export/excel")
@permission_required("can_manage_inventory")
def inventory_export_excel():
    q = request.args.get("q", "").strip()
    db = get_db()
    items = get_active_inventory(db, q)

    wb = Workbook()
    ws = wb.active
    ws.title = "Stock List"
    headers = ["SKU", "Item Name", "Size", "Version", "Category", "Brand",
               "Cost Price (₱)", "Selling Price (₱)", "Quantity", "Unit", "Barcode"]
    ws.append(headers)
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="FF6A2B", end_color="FF6A2B", fill_type="solid")
    for col_num in range(1, len(headers) + 1):
        cell = ws.cell(row=1, column=col_num)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center")

    for i in items:
        ws.append([
            i["sku"], i["item_name"], i["size"] or "", i["version"] or "",
            i["category"], i["brand"] or "", i["cost_price"], i["selling_price"],
            i["quantity"], i["unit"], i["barcode"] or "",
        ])

    for col_cells in ws.columns:
        max_len = max((len(str(c.value)) if c.value is not None else 0) for c in col_cells)
        ws.column_dimensions[col_cells[0].column_letter].width = max_len + 3

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)

    log_audit(db, "Inventory Exported", f"Exported stock list to Excel ({len(items)} items)")
    db.commit()
    db.close()

    filename = f"DAN-J-MOTO-Stock-{datetime.now().strftime('%Y%m%d')}.xlsx"
    return send_file(buf, as_attachment=True, download_name=filename,
                      mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.route("/inventory/export/pdf")
@permission_required("can_manage_inventory")
def inventory_export_pdf():
    q = request.args.get("q", "").strip()
    db = get_db()
    items = get_active_inventory(db, q)

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(letter),
                             topMargin=0.4 * inch, bottomMargin=0.4 * inch,
                             leftMargin=0.4 * inch, rightMargin=0.4 * inch)
    styles = getSampleStyleSheet()
    elements = [
        Paragraph("DAN J MOTO — Stock List", styles["Title"]),
        Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                  + (f" — filtered by: \"{q}\"" if q else ""), styles["Normal"]),
        Spacer(1, 14),
    ]

    # PHP prefix used instead of the ₱ symbol — the peso sign isn't included
    # in PDF's standard built-in fonts and would render as a broken box.
    data = [["SKU", "Item Name", "Size", "Version", "Category", "Brand", "Cost", "Selling", "Qty", "Unit"]]
    for i in items:
        data.append([
            i["sku"], i["item_name"], i["size"] or "-", i["version"] or "-",
            i["category"], i["brand"] or "-",
            f"PHP {i['cost_price']:.2f}", f"PHP {i['selling_price']:.2f}",
            str(i["quantity"]), i["unit"],
        ])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#FF6A2B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(table)
    doc.build(elements)
    buf.seek(0)

    log_audit(db, "Inventory Exported", f"Exported stock list to PDF ({len(items)} items)")
    db.commit()
    db.close()

    filename = f"DAN-J-MOTO-Stock-{datetime.now().strftime('%Y%m%d')}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="application/pdf")


@app.route("/inventory/add", methods=["GET", "POST"])
@permission_required("can_manage_inventory")
def inventory_add():
    db = get_db()
    if request.method == "POST":
        item_name = request.form["item_name"].strip()
        category = request.form.get("category", "General").strip() or "General"
        brand = request.form.get("brand", "").strip()
        cost_price = float(request.form.get("cost_price") or 0)
        selling_price = float(request.form.get("selling_price") or 0)
        quantity = int(request.form.get("quantity") or 0)
        unit = request.form.get("unit", "pcs").strip() or "pcs"
        low_stock_threshold = int(request.form.get("low_stock_threshold") or 5)
        barcode = request.form.get("barcode", "").strip() or None
        size = request.form.get("size", "").strip() or None
        version = request.form.get("version", "").strip() or None
        now = datetime.now().isoformat(timespec="seconds")

        # If a barcode was scanned/entered, that's the most reliable way to
        # find a matching item — manufacturer barcodes are already unique
        # per size/version variant.
        existing = None
        barcode_conflict = None
        if barcode:
            barcode_match = db.execute(
                "SELECT * FROM inventory WHERE barcode = ?", (barcode,)
            ).fetchone()
            if barcode_match:
                # A barcode should only ever mean "the exact same item".
                # If the size or version doesn't match, this is very likely
                # a mistake — e.g. reusing the previous item's barcode by
                # accident — rather than genuinely the same product. Flag it
                # instead of silently merging different sizes together.
                same_size = (barcode_match["size"] or None) == size
                same_version = (barcode_match["version"] or None) == version
                if same_size and same_version:
                    existing = barcode_match
                else:
                    barcode_conflict = barcode_match

        if barcode_conflict:
            db.close()
            conflict_desc = barcode_conflict["item_name"]
            if barcode_conflict["size"]:
                conflict_desc += f" (size {barcode_conflict['size']})"
            flash(
                f"This barcode is already used by '{conflict_desc}'. Each size/version needs "
                f"its own unique barcode — please double-check the barcode you scanned/typed, "
                f"or leave it blank if this is genuinely a new item.",
                "error",
            )
            return redirect(url_for("inventory_add"))

        # Fall back to matching by name + brand + size + version (manual
        # entry, no barcode) — size/version matter here because a helmet in
        # size M and the same helmet in size XL are different stock items.
        if existing is None and not barcode:
            existing = db.execute(
                """SELECT * FROM inventory WHERE item_name = ? AND IFNULL(brand,'') = IFNULL(?,'')
                   AND IFNULL(size,'') = IFNULL(?,'') AND IFNULL(version,'') = IFNULL(?,'')""",
                (item_name, brand, size, version),
            ).fetchone()

        if existing:
            was_reactivated = existing["is_active"] == 0
            new_qty = existing["quantity"] + quantity
            db.execute(
                """UPDATE inventory SET quantity=?, cost_price=?, selling_price=?,
                   last_updated=?, is_active=1 WHERE id=?""",
                (new_qty, cost_price or existing["cost_price"],
                 selling_price or existing["selling_price"], now, existing["id"]),
            )
            db.execute(
                """INSERT INTO stock_log (item_id, change_qty, reason, note, log_date, by_user)
                   VALUES (?,?,?,?,?,?)""",
                (existing["id"], quantity, "restock", "Added to existing item", now, session["user_id"]),
            )
            db.commit()
            reactivate_note = " (item was previously deleted — automatically restored)" if was_reactivated else ""
            log_audit(db, "Stock Added",
                      f"Added {quantity} {unit} to '{existing['item_name']}' ({existing['sku']}) — new total {new_qty}{reactivate_note}")
            db.commit()
            flash(f"Added {quantity} {unit} to existing stock of '{existing['item_name']}'. New quantity: {new_qty}.", "success")
        else:
            sku = next_sku(db)
            cur = db.execute(
                """INSERT INTO inventory
                   (sku, item_name, category, brand, cost_price, selling_price, quantity,
                    unit, low_stock_threshold, date_added, last_updated, added_by, barcode, size, version)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (sku, item_name, category, brand, cost_price, selling_price, quantity,
                 unit, low_stock_threshold, now, now, session["user_id"], barcode, size, version),
            )
            db.execute(
                """INSERT INTO stock_log (item_id, change_qty, reason, note, log_date, by_user)
                   VALUES (?,?,?,?,?,?)""",
                (cur.lastrowid, quantity, "new item", "Initial stock", now, session["user_id"]),
            )
            db.commit()
            log_audit(db, "Item Added", f"Created new item '{item_name}' ({sku}) with {quantity} {unit}")
            db.commit()
            flash(f"New item '{item_name}' added ({sku}) with {quantity} {unit} in stock.", "success")
        db.close()
        return redirect(url_for("inventory_list"))
    db.close()
    return render_template("inventory_add.html")


@app.route("/api/lookup-barcode/<barcode>")
@permission_required("can_manage_inventory")
def api_lookup_barcode(barcode):
    """Used by the Add Stock page: scan a manufacturer barcode and check if
    this item already exists, so the form can be pre-filled or left blank
    for a brand-new item."""
    db = get_db()
    item = db.execute("SELECT * FROM inventory WHERE barcode = ?", (barcode,)).fetchone()
    db.close()
    if item is None:
        return {"found": False}
    return {
        "found": True,
        "item_name": item["item_name"],
        "category": item["category"],
        "brand": item["brand"],
        "cost_price": item["cost_price"],
        "selling_price": item["selling_price"],
        "quantity": item["quantity"],
        "unit": item["unit"],
        "size": item["size"],
        "version": item["version"],
    }


@app.route("/inventory/<int:item_id>/edit", methods=["GET", "POST"])
@permission_required("can_manage_inventory")
def inventory_edit(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM inventory WHERE id=?", (item_id,)).fetchone()
    if item is None:
        db.close()
        flash("Item not found.", "error")
        return redirect(url_for("inventory_list"))
    if request.method == "POST":
        item_name = request.form["item_name"].strip()
        category = request.form.get("category", "General").strip() or "General"
        brand = request.form.get("brand", "").strip()
        cost_price = float(request.form.get("cost_price") or 0)
        selling_price = float(request.form.get("selling_price") or 0)
        low_stock_threshold = int(request.form.get("low_stock_threshold") or 5)
        barcode = request.form.get("barcode", "").strip() or None
        size = request.form.get("size", "").strip() or None
        version = request.form.get("version", "").strip() or None
        adjust_qty = int(request.form.get("adjust_qty") or 0)
        now = datetime.now().isoformat(timespec="seconds")
        new_qty = item["quantity"] + adjust_qty
        db.execute(
            """UPDATE inventory SET item_name=?, category=?, brand=?, cost_price=?,
               selling_price=?, low_stock_threshold=?, quantity=?, last_updated=?, barcode=?, size=?, version=? WHERE id=?""",
            (item_name, category, brand, cost_price, selling_price,
             low_stock_threshold, new_qty, now, barcode, size, version, item_id),
        )
        if adjust_qty != 0:
            db.execute(
                """INSERT INTO stock_log (item_id, change_qty, reason, note, log_date, by_user)
                   VALUES (?,?,?,?,?,?)""",
                (item_id, adjust_qty, "adjustment", "Manual edit", now, session["user_id"]),
            )
        db.commit()
        change_note = f" (qty adjusted by {adjust_qty:+d})" if adjust_qty != 0 else ""
        log_audit(db, "Item Edited", f"Edited '{item_name}' ({item['sku']}){change_note}")
        db.commit()
        db.close()
        flash(f"'{item_name}' updated.", "success")
        return redirect(url_for("inventory_list"))
    db.close()
    return render_template("inventory_edit.html", item=item)


@app.route("/inventory/<int:item_id>/delete", methods=["POST"])
@permission_required("can_manage_inventory")
def inventory_delete(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM inventory WHERE id=?", (item_id,)).fetchone()
    if item is None:
        db.close()
        flash("Item not found.", "error")
        return redirect(url_for("inventory_list"))

    # Soft delete: the item is hidden from the stock list and sales screen,
    # but its record — and every past sale/receipt that mentions it — stays
    # fully intact for accurate historical records and audit purposes.
    now = datetime.now().isoformat(timespec="seconds")
    db.execute("UPDATE inventory SET is_active = 0, last_updated = ? WHERE id = ?", (now, item_id))
    db.commit()
    log_audit(db, "Item Deleted", f"Deleted '{item['item_name']}' ({item['sku']}) — had {item['quantity']} {item['unit']} in stock")
    db.commit()
    db.close()
    flash(f"'{item['item_name']}' was removed from the stock list.", "success")
    return redirect(url_for("inventory_list"))


@app.route("/inventory/<int:item_id>/label")
@permission_required("can_manage_inventory")
def inventory_label(item_id):
    db = get_db()
    item = db.execute("SELECT * FROM inventory WHERE id=?", (item_id,)).fetchone()
    db.close()
    if item is None:
        flash("Item not found.", "error")
        return redirect(url_for("inventory_list"))
    return render_template("inventory_label.html", item=item)


@app.route("/api/lookup/<code>")
@permission_required("can_manage_sales")
def api_lookup_item(code):
    db = get_db()
    item = db.execute(
        "SELECT * FROM inventory WHERE (sku = ? OR barcode = ?) AND is_active = 1", (code, code)
    ).fetchone()
    db.close()
    if item is None:
        return {"found": False}, 404
    return {
        "found": True,
        "id": item["id"],
        "sku": item["sku"],
        "name": item["item_name"],
        "price": item["selling_price"],
        "stock": item["quantity"],
    }


# ---------------------------------------------------------------------------
# Point of Sale
# ---------------------------------------------------------------------------
@app.route("/sales/new", methods=["GET", "POST"])
@permission_required("can_manage_sales")
def sales_new():
    db = get_db()
    if request.method == "POST":
        buyer_name = request.form.get("buyer_name", "").strip() or "Walk-in Customer"
        buyer_contact = request.form.get("buyer_contact", "").strip()
        payment_method = request.form.get("payment_method", "Cash")
        discount_amount = float(request.form.get("discount_amount") or 0)
        cash_received_raw = request.form.get("cash_received", "").strip()
        cash_received = float(cash_received_raw) if cash_received_raw else None

        item_ids = request.form.getlist("item_id[]")
        quantities = request.form.getlist("quantity[]")

        cart = []
        subtotal = 0.0
        error = None
        for item_id, qty_raw in zip(item_ids, quantities):
            if not item_id or not qty_raw:
                continue
            qty = int(qty_raw)
            if qty <= 0:
                continue
            item = db.execute("SELECT * FROM inventory WHERE id=?", (item_id,)).fetchone()
            if item is None:
                continue
            if qty > item["quantity"]:
                error = f"Not enough stock for '{item['item_name']}' (only {item['quantity']} left)."
                break
            line_subtotal = item["selling_price"] * qty
            subtotal += line_subtotal
            cart.append({
                "item": item, "qty": qty, "line_subtotal": line_subtotal
            })

        if error:
            flash(error, "error")
        elif not cart:
            flash("Add at least one item with a valid quantity.", "error")
        elif discount_amount < 0 or discount_amount > subtotal:
            flash("Discount amount can't be negative or greater than the subtotal.", "error")
        elif payment_method == "Cash" and cash_received is not None and cash_received < round(subtotal - discount_amount, 2):
            flash("Cash received is less than the total amount due.", "error")
        else:
            discount_amount = round(discount_amount, 2)
            total = round(subtotal - discount_amount, 2)
            change_amount = round(cash_received - total, 2) if cash_received is not None else None
            now = datetime.now()
            receipt_no = next_receipt_no(db)
            cur = db.execute(
                """INSERT INTO sales
                   (receipt_no, sale_date, sale_datetime, buyer_name, buyer_contact,
                    subtotal, discount_percent, discount_amount, total, payment_method, cashier_id,
                    cash_received, change_amount)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (receipt_no, now.strftime("%Y-%m-%d"), now.isoformat(timespec="seconds"),
                 buyer_name, buyer_contact, round(subtotal, 2), 0,
                 discount_amount, total, payment_method, session["user_id"],
                 cash_received, change_amount),
            )
            sale_id = cur.lastrowid
            for row in cart:
                item = row["item"]
                db.execute(
                    """INSERT INTO sale_items (sale_id, item_id, item_name, unit_price, unit_cost, quantity, line_subtotal)
                       VALUES (?,?,?,?,?,?,?)""",
                    (sale_id, item["id"], item["item_name"], item["selling_price"], item["cost_price"], row["qty"], row["line_subtotal"]),
                )
                new_qty = item["quantity"] - row["qty"]
                db.execute("UPDATE inventory SET quantity=?, last_updated=? WHERE id=?",
                           (new_qty, now.isoformat(timespec="seconds"), item["id"]))
                db.execute(
                    """INSERT INTO stock_log (item_id, change_qty, reason, note, log_date, by_user)
                       VALUES (?,?,?,?,?,?)""",
                    (item["id"], -row["qty"], "sale", f"Receipt {receipt_no}",
                     now.isoformat(timespec="seconds"), session["user_id"]),
                )
            db.commit()
            log_audit(db, "Sale Completed",
                      f"Receipt {receipt_no} — {buyer_name} — ₱{total:.2f}" + (f" (discount ₱{discount_amount:.2f})" if discount_amount > 0 else ""))
            db.commit()
            db.close()
            flash(f"Sale completed. Receipt {receipt_no}.", "success")
            return redirect(url_for("sales_receipt", sale_id=sale_id))

    items = db.execute("SELECT * FROM inventory WHERE quantity > 0 AND is_active = 1 ORDER BY item_name").fetchall()
    db.close()
    return render_template("sales_new.html", items=items)


@app.route("/sales/receipt/<int:sale_id>")
@permission_required("can_manage_sales")
def sales_receipt(sale_id):
    db = get_db()
    sale = db.execute("SELECT * FROM sales WHERE id=?", (sale_id,)).fetchone()
    if sale is None:
        db.close()
        flash("Receipt not found.", "error")
        return redirect(url_for("sales_history"))
    items = db.execute("SELECT * FROM sale_items WHERE sale_id=?", (sale_id,)).fetchall()
    cashier = db.execute("SELECT full_name FROM users WHERE id=?", (sale["cashier_id"],)).fetchone()
    db.close()
    return render_template("receipt.html", sale=sale, items=items,
                            cashier_name=(cashier["full_name"] if cashier else "—"))


@app.route("/sales/history")
@permission_required("can_view_reports")
def sales_history():
    date_filter = request.args.get("date", "").strip()
    month_filter = request.args.get("month", "").strip()
    buyer_filter = request.args.get("buyer", "").strip()

    query = "SELECT * FROM sales WHERE 1=1"
    params = []
    if date_filter:
        query += " AND sale_date = ?"
        params.append(date_filter)
    if month_filter:
        query += " AND sale_date LIKE ?"
        params.append(month_filter + "%")
    if buyer_filter:
        query += " AND buyer_name LIKE ?"
        params.append(f"%{buyer_filter}%")
    query += " ORDER BY id DESC"

    db = get_db()
    sales = db.execute(query, params).fetchall()
    total_sum = sum(s["total"] for s in sales)
    db.close()
    return render_template(
        "sales_history.html", sales=sales, date_filter=date_filter,
        month_filter=month_filter, buyer_filter=buyer_filter, total_sum=total_sum
    )


# ---------------------------------------------------------------------------
# Suppliers
# ---------------------------------------------------------------------------
@app.route("/suppliers")
@permission_required("can_manage_purchasing")
def suppliers_list():
    db = get_db()
    suppliers = db.execute("SELECT * FROM suppliers ORDER BY name").fetchall()
    db.close()
    return render_template("suppliers_list.html", suppliers=suppliers)


@app.route("/suppliers/add", methods=["GET", "POST"])
@permission_required("can_manage_purchasing")
def suppliers_add():
    if request.method == "POST":
        name = request.form["name"].strip()
        if not name:
            flash("Supplier name is required.", "error")
        else:
            db = get_db()
            db.execute(
                """INSERT INTO suppliers (name, contact_person, phone, email, address, notes, is_active, created_at)
                   VALUES (?,?,?,?,?,?,1,?)""",
                (name, request.form.get("contact_person", "").strip(),
                 request.form.get("phone", "").strip(), request.form.get("email", "").strip(),
                 request.form.get("address", "").strip(), request.form.get("notes", "").strip(),
                 datetime.now().isoformat(timespec="seconds")),
            )
            db.commit()
            log_audit(db, "Supplier Added", f"Added supplier '{name}'")
            db.commit()
            db.close()
            flash(f"Supplier '{name}' added.", "success")
            return redirect(url_for("suppliers_list"))
    return render_template("suppliers_add.html")


@app.route("/suppliers/<int:supplier_id>/edit", methods=["GET", "POST"])
@permission_required("can_manage_purchasing")
def suppliers_edit(supplier_id):
    db = get_db()
    supplier = db.execute("SELECT * FROM suppliers WHERE id=?", (supplier_id,)).fetchone()
    if supplier is None:
        db.close()
        flash("Supplier not found.", "error")
        return redirect(url_for("suppliers_list"))
    if request.method == "POST":
        name = request.form["name"].strip()
        is_active = 1 if request.form.get("is_active") else 0
        db.execute(
            """UPDATE suppliers SET name=?, contact_person=?, phone=?, email=?, address=?, notes=?, is_active=?
               WHERE id=?""",
            (name, request.form.get("contact_person", "").strip(),
             request.form.get("phone", "").strip(), request.form.get("email", "").strip(),
             request.form.get("address", "").strip(), request.form.get("notes", "").strip(),
             is_active, supplier_id),
        )
        db.commit()
        log_audit(db, "Supplier Updated", f"Updated supplier '{name}'")
        db.commit()
        db.close()
        flash(f"Supplier '{name}' updated.", "success")
        return redirect(url_for("suppliers_list"))
    db.close()
    return render_template("suppliers_edit.html", supplier=supplier)


# ---------------------------------------------------------------------------
# Purchase Orders
# ---------------------------------------------------------------------------
@app.route("/purchase-orders")
@permission_required("can_manage_purchasing")
def purchase_orders_list():
    status_filter = request.args.get("status", "").strip()
    db = get_db()
    query = """
        SELECT po.*, s.name AS supplier_name
        FROM purchase_orders po
        JOIN suppliers s ON s.id = po.supplier_id
        WHERE 1=1
    """
    params = []
    if status_filter:
        query += " AND po.status = ?"
        params.append(status_filter)
    query += " ORDER BY po.id DESC"
    orders = db.execute(query, params).fetchall()
    db.close()
    return render_template("purchase_orders_list.html", orders=orders, status_filter=status_filter)


@app.route("/purchase-orders/new", methods=["GET", "POST"])
@permission_required("can_manage_purchasing")
def purchase_orders_new():
    db = get_db()
    if request.method == "POST":
        supplier_id = request.form.get("supplier_id")
        notes = request.form.get("notes", "").strip()
        item_ids = request.form.getlist("item_id[]")
        quantities = request.form.getlist("quantity[]")
        unit_costs = request.form.getlist("unit_cost[]")

        if not supplier_id:
            flash("Please select a supplier.", "error")
            return redirect(url_for("purchase_orders_new"))

        lines = []
        total_cost = 0.0
        for item_id, qty_raw, cost_raw in zip(item_ids, quantities, unit_costs):
            if not item_id or not qty_raw:
                continue
            qty = int(qty_raw)
            cost = float(cost_raw or 0)
            if qty <= 0:
                continue
            item = db.execute("SELECT * FROM inventory WHERE id=?", (item_id,)).fetchone()
            if item is None:
                continue
            line_total = qty * cost
            total_cost += line_total
            lines.append({"item": item, "qty": qty, "cost": cost, "line_total": line_total})

        if not lines:
            flash("Add at least one item with a valid quantity.", "error")
            db.close()
            return redirect(url_for("purchase_orders_new"))

        supplier = db.execute("SELECT * FROM suppliers WHERE id=?", (supplier_id,)).fetchone()
        po_number = next_po_number(db)
        now = datetime.now()
        cur = db.execute(
            """INSERT INTO purchase_orders (po_number, supplier_id, status, order_date, notes, total_cost, created_by)
               VALUES (?,?,?,?,?,?,?)""",
            (po_number, supplier_id, "pending", now.strftime("%Y-%m-%d"), notes, round(total_cost, 2), session["user_id"]),
        )
        po_id = cur.lastrowid
        for line in lines:
            db.execute(
                """INSERT INTO purchase_order_items (po_id, item_id, item_name, quantity_ordered, unit_cost, line_total)
                   VALUES (?,?,?,?,?,?)""",
                (po_id, line["item"]["id"], line["item"]["item_name"], line["qty"], line["cost"], line["line_total"]),
            )
        db.commit()
        log_audit(db, "Purchase Order Created",
                  f"Created {po_number} for supplier '{supplier['name']}' — {len(lines)} item(s), ₱{total_cost:.2f}")
        db.commit()
        db.close()
        flash(f"Purchase order {po_number} created.", "success")
        return redirect(url_for("purchase_orders_view", po_id=po_id))

    suppliers = db.execute("SELECT * FROM suppliers WHERE is_active = 1 ORDER BY name").fetchall()
    items = db.execute("SELECT * FROM inventory WHERE is_active = 1 ORDER BY item_name").fetchall()
    db.close()
    if not suppliers:
        flash("Add a supplier first before creating a purchase order.", "error")
        return redirect(url_for("suppliers_add"))
    return render_template("purchase_order_new.html", suppliers=suppliers, items=items)


@app.route("/purchase-orders/<int:po_id>")
@permission_required("can_manage_purchasing")
def purchase_orders_view(po_id):
    db = get_db()
    po = db.execute(
        """SELECT po.*, s.name AS supplier_name, s.contact_person, s.phone
           FROM purchase_orders po JOIN suppliers s ON s.id = po.supplier_id
           WHERE po.id = ?""", (po_id,)
    ).fetchone()
    if po is None:
        db.close()
        flash("Purchase order not found.", "error")
        return redirect(url_for("purchase_orders_list"))
    line_items = db.execute("SELECT * FROM purchase_order_items WHERE po_id = ?", (po_id,)).fetchall()
    db.close()
    return render_template("purchase_order_view.html", po=po, line_items=line_items)


@app.route("/purchase-orders/<int:po_id>/receive", methods=["POST"])
@permission_required("can_manage_purchasing")
def purchase_orders_receive(po_id):
    db = get_db()
    po = db.execute("SELECT * FROM purchase_orders WHERE id=?", (po_id,)).fetchone()
    if po is None or po["status"] in ("received", "cancelled"):
        db.close()
        flash("This purchase order can't be received.", "error")
        return redirect(url_for("purchase_orders_list"))

    line_items = db.execute("SELECT * FROM purchase_order_items WHERE po_id = ?", (po_id,)).fetchall()
    now = datetime.now().isoformat(timespec="seconds")
    any_received = False
    fully_received = True

    for line in line_items:
        remaining = line["quantity_ordered"] - line["quantity_received"]
        received_now_raw = request.form.get(f"receive_{line['id']}", "0").strip()
        received_now = int(received_now_raw) if received_now_raw else 0
        received_now = max(0, min(received_now, remaining))

        if received_now > 0:
            any_received = True
            new_received_total = line["quantity_received"] + received_now
            db.execute("UPDATE purchase_order_items SET quantity_received=? WHERE id=?",
                       (new_received_total, line["id"]))
            item = db.execute("SELECT * FROM inventory WHERE id=?", (line["item_id"],)).fetchone()
            new_qty = item["quantity"] + received_now
            db.execute("UPDATE inventory SET quantity=?, last_updated=?, is_active=1 WHERE id=?",
                       (new_qty, now, item["id"]))
            db.execute(
                """INSERT INTO stock_log (item_id, change_qty, reason, note, log_date, by_user)
                   VALUES (?,?,?,?,?,?)""",
                (item["id"], received_now, "purchase", f"Received from {po['po_number']}", now, session["user_id"]),
            )
            if new_received_total < line["quantity_ordered"]:
                fully_received = False
        elif line["quantity_received"] < line["quantity_ordered"]:
            fully_received = False

    if not any_received:
        db.close()
        flash("Enter at least one quantity to receive.", "error")
        return redirect(url_for("purchase_orders_view", po_id=po_id))

    new_status = "received" if fully_received else "partial"
    received_date = now if fully_received else po["received_date"]
    db.execute("UPDATE purchase_orders SET status=?, received_date=? WHERE id=?",
               (new_status, received_date, po_id))
    db.commit()
    log_audit(db, "Purchase Order Received", f"Received stock for {po['po_number']} — status now {new_status}")
    db.commit()
    db.close()
    flash(f"Stock received for {po['po_number']}.", "success")
    return redirect(url_for("purchase_orders_view", po_id=po_id))


@app.route("/purchase-orders/<int:po_id>/cancel", methods=["POST"])
@permission_required("can_manage_purchasing")
def purchase_orders_cancel(po_id):
    db = get_db()
    po = db.execute("SELECT * FROM purchase_orders WHERE id=?", (po_id,)).fetchone()
    if po is None or po["status"] != "pending":
        db.close()
        flash("Only a pending order with nothing received yet can be cancelled.", "error")
        return redirect(url_for("purchase_orders_list"))
    db.execute("UPDATE purchase_orders SET status='cancelled' WHERE id=?", (po_id,))
    db.commit()
    log_audit(db, "Purchase Order Cancelled", f"Cancelled {po['po_number']}")
    db.commit()
    db.close()
    flash(f"{po['po_number']} was cancelled.", "success")
    return redirect(url_for("purchase_orders_list"))


@app.route("/reports/best-sellers")
@permission_required("can_view_reports")
def best_sellers_report():
    date_filter = request.args.get("date", "").strip()
    month_filter = request.args.get("month", "").strip()

    query = """
        SELECT si.item_name, SUM(si.quantity) AS total_qty, SUM(si.line_subtotal) AS total_revenue,
               COUNT(DISTINCT si.sale_id) AS num_sales
        FROM sale_items si JOIN sales s ON s.id = si.sale_id
        WHERE 1=1
    """
    params = []
    if date_filter:
        query += " AND s.sale_date = ?"
        params.append(date_filter)
    if month_filter:
        query += " AND s.sale_date LIKE ?"
        params.append(month_filter + "%")
    query += " GROUP BY si.item_name ORDER BY total_qty DESC LIMIT 20"

    db = get_db()
    rows = db.execute(query, params).fetchall()
    db.close()
    return render_template("best_sellers.html", rows=rows, date_filter=date_filter, month_filter=month_filter)


@app.route("/reports/slow-movers")
@permission_required("can_view_reports")
def slow_movers_report():
    days = int(request.args.get("days", 90))
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

    db = get_db()
    rows = db.execute(
        """
        SELECT i.id, i.item_name, i.sku, i.size, i.version, i.quantity AS current_stock,
               COALESCE(SUM(CASE WHEN s.sale_date >= ? THEN si.quantity ELSE 0 END), 0) AS qty_sold_period,
               MAX(s.sale_date) AS last_sold_date
        FROM inventory i
        LEFT JOIN sale_items si ON si.item_id = i.id
        LEFT JOIN sales s ON s.id = si.sale_id
        WHERE i.is_active = 1
        GROUP BY i.id
        ORDER BY qty_sold_period ASC, i.item_name ASC
        LIMIT 50
        """,
        (cutoff,),
    ).fetchall()
    db.close()
    return render_template("slow_movers.html", rows=rows, days=days)


@app.route("/reports/inventory-valuation")
@admin_required
def inventory_valuation_report():
    db = get_db()
    items = db.execute("SELECT * FROM inventory WHERE is_active = 1 ORDER BY item_name").fetchall()
    db.close()

    rows = []
    total_cost_value = 0.0
    total_retail_value = 0.0
    for i in items:
        cost_value = i["cost_price"] * i["quantity"]
        retail_value = i["selling_price"] * i["quantity"]
        rows.append({**dict(i), "cost_value": cost_value, "retail_value": retail_value})
        total_cost_value += cost_value
        total_retail_value += retail_value

    return render_template(
        "inventory_valuation.html", rows=rows,
        total_cost_value=total_cost_value, total_retail_value=total_retail_value,
        total_potential_profit=total_retail_value - total_cost_value,
    )


@app.route("/reports/stock-movement")
@permission_required("can_view_reports")
def stock_movement_report():
    date_filter = request.args.get("date", "").strip()
    reason_filter = request.args.get("reason", "").strip()
    item_filter = request.args.get("item", "").strip()

    query = """
        SELECT sl.*, i.item_name, i.sku, u.full_name AS by_user_name
        FROM stock_log sl
        JOIN inventory i ON i.id = sl.item_id
        LEFT JOIN users u ON u.id = sl.by_user
        WHERE 1=1
    """
    params = []
    if date_filter:
        query += " AND sl.log_date LIKE ?"
        params.append(date_filter + "%")
    if reason_filter:
        query += " AND sl.reason = ?"
        params.append(reason_filter)
    if item_filter:
        query += " AND i.item_name LIKE ?"
        params.append(f"%{item_filter}%")
    query += " ORDER BY sl.id DESC LIMIT 300"

    db = get_db()
    logs = db.execute(query, params).fetchall()
    reasons = db.execute("SELECT DISTINCT reason FROM stock_log ORDER BY reason").fetchall()
    db.close()
    return render_template(
        "stock_movement.html", logs=logs, reasons=reasons,
        date_filter=date_filter, reason_filter=reason_filter, item_filter=item_filter
    )


@app.route("/reports/profit")
@admin_required
def profit_report():
    date_filter = request.args.get("date", "").strip()
    month_filter = request.args.get("month", "").strip()

    query = """
        SELECT s.*, COALESCE(SUM(si.unit_cost * si.quantity), 0) AS cogs
        FROM sales s
        LEFT JOIN sale_items si ON si.sale_id = s.id
        WHERE 1=1
    """
    params = []
    if date_filter:
        query += " AND s.sale_date = ?"
        params.append(date_filter)
    if month_filter:
        query += " AND s.sale_date LIKE ?"
        params.append(month_filter + "%")
    query += " GROUP BY s.id ORDER BY s.id DESC"

    db = get_db()
    rows = db.execute(query, params).fetchall()
    db.close()

    sales_with_profit = []
    totals = {"gross_sales": 0.0, "discounts": 0.0, "net_sales": 0.0, "cogs": 0.0, "gross_profit": 0.0}
    for r in rows:
        gross_profit = round(r["total"] - r["cogs"], 2)
        sales_with_profit.append({**dict(r), "gross_profit": gross_profit})
        totals["gross_sales"] += r["subtotal"]
        totals["discounts"] += r["discount_amount"]
        totals["net_sales"] += r["total"]
        totals["cogs"] += r["cogs"]
        totals["gross_profit"] += gross_profit

    margin = (totals["gross_profit"] / totals["net_sales"] * 100) if totals["net_sales"] > 0 else 0

    return render_template(
        "profit_report.html", sales=sales_with_profit, totals=totals, margin=margin,
        date_filter=date_filter, month_filter=month_filter
    )


# ---------------------------------------------------------------------------
# Backup & Restore
# ---------------------------------------------------------------------------
@app.route("/admin/backup")
@admin_required
def admin_backup():
    if not os.path.exists(DB_PATH):
        flash("No database file found to back up.", "error")
        return redirect(url_for("dashboard"))
    db = get_db()
    log_audit(db, "Database Backup Downloaded", "Downloaded a full database backup")
    db.commit()
    db.close()
    filename = f"DAN-J-MOTO-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
    return send_file(DB_PATH, as_attachment=True, download_name=filename,
                      mimetype="application/octet-stream")


def _looks_like_valid_backup(filepath):
    """Basic sanity check before restoring: is this actually a SQLite file
    with the tables this app expects? Prevents accidentally wiping the
    database with an unrelated or corrupted file."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(16)
        if not header.startswith(b"SQLite format 3"):
            return False, "That file doesn't look like a valid database file."
        import sqlite3
        conn = sqlite3.connect(filepath)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        required = {"users", "inventory", "sales"}
        if not required.issubset(tables):
            return False, "This file is missing expected tables — it doesn't look like a DAN J MOTO backup."
        return True, None
    except Exception as e:
        return False, f"Couldn't read this file as a database: {e}"


@app.route("/admin/restore", methods=["GET", "POST"])
@admin_required
def admin_restore():
    if request.method == "POST":
        uploaded = request.files.get("backup_file")
        if not uploaded or uploaded.filename == "":
            flash("Please choose a backup file to restore.", "error")
            return redirect(url_for("admin_restore"))

        temp_path = "restore_upload_temp.db"
        uploaded.save(temp_path)

        is_valid, error_msg = _looks_like_valid_backup(temp_path)
        if not is_valid:
            os.remove(temp_path)
            flash(f"Restore cancelled: {error_msg}", "error")
            return redirect(url_for("admin_restore"))

        # Safety net: keep a copy of the current database before overwriting,
        # in case the restore turns out to be a mistake.
        if os.path.exists(DB_PATH):
            safety_backup = f"motorshop_before_restore_{datetime.now().strftime('%Y%m%d%H%M%S')}.db"
            import shutil
            shutil.copy2(DB_PATH, safety_backup)

        import shutil
        shutil.move(temp_path, DB_PATH)

        db = get_db()
        log_audit(db, "Database Restored", f"Restored database from an uploaded backup file: {uploaded.filename}")
        db.commit()
        db.close()

        session.clear()
        flash("Database restored successfully. A copy of your previous database was saved "
              "in the app folder just in case, named 'motorshop_before_restore_...'.", "success")
        return redirect(url_for("login"))

    return render_template("admin_restore.html")


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------
@app.route("/audit-log")
@admin_required
def audit_log_view():
    action_filter = request.args.get("action", "").strip()
    user_filter = request.args.get("user", "").strip()
    date_filter = request.args.get("date", "").strip()

    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []
    if action_filter:
        query += " AND action = ?"
        params.append(action_filter)
    if user_filter:
        query += " AND performed_by_name LIKE ?"
        params.append(f"%{user_filter}%")
    if date_filter:
        query += " AND created_at LIKE ?"
        params.append(date_filter + "%")
    query += " ORDER BY id DESC LIMIT 300"

    db = get_db()
    logs = db.execute(query, params).fetchall()
    action_types = db.execute("SELECT DISTINCT action FROM audit_log ORDER BY action").fetchall()
    db.close()
    return render_template(
        "audit_log.html", logs=logs, action_types=action_types,
        action_filter=action_filter, user_filter=user_filter, date_filter=date_filter
    )


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    import os as _os
    cert_exists = _os.path.exists("cert.pem") and _os.path.exists("key.pem")
    if cert_exists:
        print("HTTPS certificate found — starting on https://0.0.0.0:5000")
        print("(camera scanning will work on phones over your WiFi)")
        app.run(debug=False, host="0.0.0.0", port=5000, ssl_context=("cert.pem", "key.pem"))
    else:
        print("No HTTPS certificate found — starting on http://0.0.0.0:5000")
        print("(camera scanning will NOT work on other devices — run generate_cert.py to enable it)")
        app.run(debug=False, host="0.0.0.0", port=5000)
