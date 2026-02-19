from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3, hashlib, os
from datetime import datetime, date
from functools import wraps

app = Flask(__name__)
app.secret_key = 'dexinv_secret_key_2024_ultra'
DB = 'dexinv.db'

# ── DB ───────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def init_db():
    conn = get_db(); c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            address TEXT,
            city TEXT,
            state TEXT,
            zip TEXT,
            country TEXT DEFAULT 'US',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            company_id INTEGER,
            last_login TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(company_id) REFERENCES companies(id)
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            sku TEXT UNIQUE NOT NULL,
            category TEXT,
            quantity INTEGER DEFAULT 0,
            price REAL DEFAULT 0.0,
            threshold INTEGER DEFAULT 10,
            company_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(company_id) REFERENCES companies(id)
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY,
            product_id INTEGER,
            product_name TEXT,
            type TEXT,
            quantity_change INTEGER,
            note TEXT,
            user_id INTEGER,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY,
            invoice_number TEXT UNIQUE NOT NULL,
            company_id INTEGER NOT NULL,
            billed_to TEXT,
            billed_to_address TEXT,
            status TEXT DEFAULT 'draft',
            subtotal REAL DEFAULT 0,
            tax_rate REAL DEFAULT 0,
            total REAL DEFAULT 0,
            due_date TEXT,
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(company_id) REFERENCES companies(id)
        );
        CREATE TABLE IF NOT EXISTS invoice_items (
            id INTEGER PRIMARY KEY,
            invoice_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            quantity INTEGER DEFAULT 1,
            unit_price REAL DEFAULT 0,
            total REAL DEFAULT 0,
            FOREIGN KEY(invoice_id) REFERENCES invoices(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            username TEXT,
            action TEXT,
            detail TEXT,
            ip TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    # Seed admin
    c.execute("INSERT OR IGNORE INTO users (username, password, role, email) VALUES ('dex',?,'admin','admin@dexinv.com')", (hash_pw('dex'),))
    conn.commit(); conn.close()

def log_activity(action, detail=''):
    if 'user_id' not in session: return
    conn = get_db()
    conn.execute("INSERT INTO activity_log (user_id,username,action,detail,ip,timestamp) VALUES (?,?,?,?,?,?)",
        (session.get('user_id'), session.get('user'), action, detail,
         request.remote_addr, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit(); conn.close()

def log_transaction(product_id, product_name, ttype, qty_change, note=''):
    conn = get_db()
    conn.execute("INSERT INTO transactions (product_id,product_name,type,quantity_change,note,user_id,timestamp) VALUES (?,?,?,?,?,?,?)",
        (product_id, product_name, ttype, qty_change, note,
         session.get('user_id'), datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit(); conn.close()

def next_invoice_number():
    conn = get_db()
    row = conn.execute("SELECT COUNT(*) as cnt FROM invoices").fetchone()
    conn.close()
    return f"INV-{(row['cnt']+1):05d}"

# ── Auth decorators ──────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if 'user' not in session: return redirect(url_for('login'))
        return f(*a, **kw)
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if session.get('role') != 'admin': return redirect(url_for('dashboard'))
        return f(*a, **kw)
    return login_required(wrap)

# ── Login / Signup ───────────────────────────────────────────────
@app.route('/', methods=['GET','POST'])
def login():
    if 'user' in session: return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        u = request.form['username'].strip()
        p = hash_pw(request.form['password'])
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=? AND password=?", (u,p)).fetchone()
        conn.close()
        if user:
            session.update({'user': u, 'user_id': user['id'], 'role': user['role'], 'company_id': user['company_id']})
            conn = get_db()
            conn.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id']))
            conn.commit(); conn.close()
            log_activity('LOGIN', f'Logged in from {request.remote_addr}')
            return redirect(url_for('dashboard'))
        error = 'Invalid username or password.'
    return render_template('login.html', error=error)

@app.route('/signup', methods=['GET','POST'])
def signup():
    error = None
    if request.method == 'POST':
        f = request.form
        conn = get_db()
        try:
            # Create company
            conn.execute("INSERT INTO companies (name,email,address,city,state,zip,country) VALUES (?,?,?,?,?,?,?)",
                (f['company_name'], f['company_email'], f['address'], f['city'], f['state'], f['zip'], f.get('country','US')))
            conn.commit()
            company_id = conn.execute("SELECT id FROM companies WHERE email=?", (f['company_email'],)).fetchone()['id']
            # Create user linked to company
            conn.execute("INSERT INTO users (username,password,email,role,company_id) VALUES (?,?,?,?,?)",
                (f['username'], hash_pw(f['password']), f['company_email'], 'user', company_id))
            conn.commit()
            flash('Account created! Sign in below.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            error = 'Username or company email already exists.'
        finally:
            conn.close()
    return render_template('signup.html', error=error)

@app.route('/logout')
def logout():
    log_activity('LOGOUT')
    session.clear()
    return redirect(url_for('login'))

# ── Dashboard ────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    cid = session.get('company_id')

    if session['role'] == 'admin':
        products = conn.execute("SELECT * FROM products ORDER BY quantity ASC").fetchall()
        invoices_count = conn.execute("SELECT COUNT(*) as c FROM invoices").fetchone()['c']
        users_count    = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
        companies_count= conn.execute("SELECT COUNT(*) as c FROM companies").fetchone()['c']
        recent_tx = conn.execute("SELECT t.*, u.username FROM transactions t LEFT JOIN users u ON t.user_id=u.id ORDER BY t.id DESC LIMIT 8").fetchall()
        pending_inv = conn.execute("SELECT COUNT(*) as c FROM invoices WHERE status='sent'").fetchone()['c']
    else:
        products = conn.execute("SELECT * FROM products WHERE company_id=? ORDER BY quantity ASC", (cid,)).fetchall()
        invoices_count = conn.execute("SELECT COUNT(*) as c FROM invoices WHERE company_id=?", (cid,)).fetchone()['c']
        users_count = None; companies_count = None
        recent_tx = conn.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 8", (session['user_id'],)).fetchall()
        pending_inv = conn.execute("SELECT COUNT(*) as c FROM invoices WHERE company_id=? AND status='sent'", (cid,)).fetchone()['c']

    total_value = sum(p['quantity'] * p['price'] for p in products)
    low_stock = [p for p in products if p['quantity'] < p['threshold']]

    chart_labels = [p['name'][:14] for p in products]
    chart_data   = [p['quantity'] for p in products]
    chart_colors = ['#ff4d6d' if p['quantity'] < p['threshold'] else '#06d6a0' for p in products]
    conn.close()

    return render_template('dashboard.html',
        products=products, total_value=total_value, low_stock=low_stock,
        recent_tx=recent_tx, chart_labels=chart_labels, chart_data=chart_data,
        chart_colors=chart_colors, low_count=len(low_stock),
        invoices_count=invoices_count, users_count=users_count,
        companies_count=companies_count, pending_inv=pending_inv)

# ── Inventory ────────────────────────────────────────────────────
@app.route('/inventory')
@login_required
def inventory():
    q = request.args.get('q',''); cat = request.args.get('cat','')
    conn = get_db(); cid = session.get('company_id')
    query = "SELECT p.*, c.name as company_name FROM products p LEFT JOIN companies c ON p.company_id=c.id WHERE 1=1"
    params = []
    if session['role'] != 'admin':
        query += " AND p.company_id=?"; params.append(cid)
    if q:
        query += " AND (p.name LIKE ? OR p.sku LIKE ?)"; params += [f'%{q}%', f'%{q}%']
    if cat:
        query += " AND p.category=?"; params.append(cat)
    query += " ORDER BY p.name"
    products = conn.execute(query, params).fetchall()
    categories = conn.execute("SELECT DISTINCT category FROM products WHERE category IS NOT NULL").fetchall()
    conn.close()
    return render_template('inventory.html', products=products, categories=categories, q=q, cat=cat)

@app.route('/product/add', methods=['GET','POST'])
@login_required
def add_product():
    if request.method == 'POST':
        f = request.form; cid = session.get('company_id')
        if session['role'] == 'admin': cid = f.get('company_id') or None
        conn = get_db()
        try:
            conn.execute("INSERT INTO products (name,sku,category,quantity,price,threshold,company_id) VALUES (?,?,?,?,?,?,?)",
                (f['name'],f['sku'],f['category'],int(f['quantity']),float(f['price']),int(f['threshold']),cid))
            conn.commit()
            pid = conn.execute("SELECT id FROM products WHERE sku=?", (f['sku'],)).fetchone()['id']
            log_transaction(pid, f['name'], 'ADDED', int(f['quantity']), 'Initial stock')
            log_activity('ADD_PRODUCT', f['name'])
            flash('Product added!', 'success')
        except sqlite3.IntegrityError:
            flash('SKU already exists.', 'danger')
        finally: conn.close()
        return redirect(url_for('inventory'))
    conn = get_db()
    companies = conn.execute("SELECT * FROM companies").fetchall() if session['role']=='admin' else []
    conn.close()
    return render_template('product_form.html', product=None, action='Add', companies=companies)

@app.route('/product/edit/<int:pid>', methods=['GET','POST'])
@login_required
def edit_product(pid):
    conn = get_db()
    product = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if request.method == 'POST':
        f = request.form; old_qty = product['quantity']; new_qty = int(f['quantity'])
        conn.execute("UPDATE products SET name=?,sku=?,category=?,quantity=?,price=?,threshold=? WHERE id=?",
            (f['name'],f['sku'],f['category'],new_qty,float(f['price']),int(f['threshold']),pid))
        conn.commit()
        if new_qty != old_qty:
            diff = new_qty - old_qty
            log_transaction(pid, f['name'], 'RESTOCK' if diff>0 else 'ADJUSTMENT', diff, f.get('note','Edit'))
        log_activity('EDIT_PRODUCT', f['name'])
        flash('Product updated!', 'success')
        conn.close(); return redirect(url_for('inventory'))
    companies = conn.execute("SELECT * FROM companies").fetchall() if session['role']=='admin' else []
    conn.close()
    return render_template('product_form.html', product=product, action='Edit', companies=companies)

@app.route('/product/delete/<int:pid>', methods=['POST'])
@login_required
def delete_product(pid):
    conn = get_db()
    p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if p:
        log_transaction(pid, p['name'], 'DELETED', -p['quantity'], 'Removed')
        log_activity('DELETE_PRODUCT', p['name'])
        conn.execute("DELETE FROM products WHERE id=?", (pid,))
        conn.commit(); flash(f'"{p["name"]}" deleted.', 'warning')
    conn.close(); return redirect(url_for('inventory'))

@app.route('/product/adjust/<int:pid>', methods=['POST'])
@login_required
def adjust_stock(pid):
    conn = get_db()
    p = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    delta = int(request.form.get('delta',0))
    new_qty = max(0, p['quantity'] + delta)
    conn.execute("UPDATE products SET quantity=? WHERE id=?", (new_qty, pid))
    conn.commit()
    log_transaction(pid, p['name'], 'RESTOCK' if delta>0 else 'DISPATCH', delta, request.form.get('note',''))
    conn.close(); return redirect(url_for('inventory'))

# ── Invoices ─────────────────────────────────────────────────────
@app.route('/invoices')
@login_required
def invoices():
    conn = get_db(); cid = session.get('company_id')
    if session['role'] == 'admin':
        inv_list = conn.execute("SELECT i.*, c.name as company_name FROM invoices i LEFT JOIN companies c ON i.company_id=c.id ORDER BY i.id DESC").fetchall()
    else:
        inv_list = conn.execute("SELECT i.*, c.name as company_name FROM invoices i LEFT JOIN companies c ON i.company_id=c.id WHERE i.company_id=? ORDER BY i.id DESC", (cid,)).fetchall()
    conn.close()
    return render_template('invoices.html', invoices=inv_list)

@app.route('/invoices/new', methods=['GET','POST'])
@login_required
def new_invoice():
    conn = get_db(); cid = session.get('company_id')
    if request.method == 'POST':
        f = request.form
        inv_num = next_invoice_number()
        actual_cid = f.get('company_id') if session['role']=='admin' else cid
        conn.execute("INSERT INTO invoices (invoice_number,company_id,billed_to,billed_to_address,status,due_date,notes,tax_rate) VALUES (?,?,?,?,?,?,?,?)",
            (inv_num, actual_cid, f['billed_to'], f['billed_to_address'], 'draft', f.get('due_date',''), f.get('notes',''), float(f.get('tax_rate',0))))
        conn.commit()
        inv_id = conn.execute("SELECT id FROM invoices WHERE invoice_number=?", (inv_num,)).fetchone()['id']

        descs  = request.form.getlist('desc[]')
        qtys   = request.form.getlist('qty[]')
        prices = request.form.getlist('price[]')
        subtotal = 0
        for desc, qty, price in zip(descs, qtys, prices):
            if desc.strip():
                qty_i=int(qty); price_f=float(price); line_total=qty_i*price_f
                conn.execute("INSERT INTO invoice_items (invoice_id,description,quantity,unit_price,total) VALUES (?,?,?,?,?)",
                    (inv_id, desc, qty_i, price_f, line_total))
                subtotal += line_total

        tax = subtotal * float(f.get('tax_rate',0)) / 100
        total = subtotal + tax
        conn.execute("UPDATE invoices SET subtotal=?,total=? WHERE id=?", (subtotal,total,inv_id))
        conn.commit(); conn.close()
        log_activity('CREATE_INVOICE', inv_num)
        flash(f'Invoice {inv_num} created!', 'success')
        return redirect(url_for('view_invoice', inv_id=inv_id))
    companies = conn.execute("SELECT * FROM companies").fetchall()
    my_company = conn.execute("SELECT * FROM companies WHERE id=?", (cid,)).fetchone() if cid else None
    conn.close()
    return render_template('invoice_form.html', companies=companies, my_company=my_company, inv_num=next_invoice_number())

@app.route('/invoices/<int:inv_id>')
@login_required
def view_invoice(inv_id):
    conn = get_db()
    inv = conn.execute("SELECT i.*, c.name as comp_name, c.address as comp_address, c.city, c.state, c.zip, c.email as comp_email FROM invoices i LEFT JOIN companies c ON i.company_id=c.id WHERE i.id=?", (inv_id,)).fetchone()
    items = conn.execute("SELECT * FROM invoice_items WHERE invoice_id=?", (inv_id,)).fetchall()
    conn.close()
    return render_template('invoice_view.html', inv=inv, items=items)

@app.route('/invoices/<int:inv_id>/status', methods=['POST'])
@login_required
def update_invoice_status(inv_id):
    new_status = request.form.get('status')
    conn = get_db()
    conn.execute("UPDATE invoices SET status=? WHERE id=?", (new_status, inv_id))
    conn.commit(); conn.close()
    log_activity('UPDATE_INVOICE_STATUS', f'Invoice {inv_id} → {new_status}')
    flash(f'Invoice marked as {new_status}.', 'success')
    return redirect(url_for('view_invoice', inv_id=inv_id))

@app.route('/invoices/<int:inv_id>/delete', methods=['POST'])
@login_required
def delete_invoice(inv_id):
    conn = get_db()
    conn.execute("DELETE FROM invoice_items WHERE invoice_id=?", (inv_id,))
    conn.execute("DELETE FROM invoices WHERE id=?", (inv_id,))
    conn.commit(); conn.close()
    flash('Invoice deleted.', 'warning')
    return redirect(url_for('invoices'))

# ── Transactions ─────────────────────────────────────────────────
@app.route('/transactions')
@login_required
def transactions():
    conn = get_db(); cid = session.get('company_id')
    if session['role'] == 'admin':
        tx = conn.execute("SELECT t.*, u.username FROM transactions t LEFT JOIN users u ON t.user_id=u.id ORDER BY t.id DESC").fetchall()
    else:
        tx = conn.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC", (session['user_id'],)).fetchall()
    conn.close()
    return render_template('transactions.html', transactions=tx)

# ── Admin: User Management ───────────────────────────────────────
@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db()
    users = conn.execute("SELECT u.*, c.name as company_name FROM users u LEFT JOIN companies c ON u.company_id=c.id ORDER BY u.created_at DESC").fetchall()
    companies = conn.execute("SELECT * FROM companies ORDER BY name").fetchall()
    conn.close()
    return render_template('admin_users.html', users=users, companies=companies)

@app.route('/admin/users/add', methods=['POST'])
@admin_required
def admin_add_user():
    f = request.form
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username,password,email,role,company_id) VALUES (?,?,?,?,?)",
            (f['username'], hash_pw(f['password']), f.get('email',''), f.get('role','user'), f.get('company_id') or None))
        conn.commit()
        log_activity('ADMIN_ADD_USER', f['username'])
        flash(f'User "{f["username"]}" added.', 'success')
    except sqlite3.IntegrityError:
        flash('Username already exists.', 'danger')
    finally: conn.close()
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:uid>', methods=['POST'])
@admin_required
def admin_delete_user(uid):
    if uid == session['user_id']:
        flash("Can't delete your own account.", 'danger')
        return redirect(url_for('admin_users'))
    conn = get_db()
    u = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
    if u:
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.commit()
        log_activity('ADMIN_DELETE_USER', u['username'])
        flash(f'User "{u["username"]}" deleted.', 'warning')
    conn.close()
    return redirect(url_for('admin_users'))

@app.route('/admin/activity')
@admin_required
def admin_activity():
    conn = get_db()
    logs = conn.execute("SELECT * FROM activity_log ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return render_template('admin_activity.html', logs=logs)

@app.route('/admin/companies')
@admin_required
def admin_companies():
    conn = get_db()
    companies = conn.execute("SELECT c.*, COUNT(u.id) as user_count, COUNT(p.id) as product_count FROM companies c LEFT JOIN users u ON u.company_id=c.id LEFT JOIN products p ON p.company_id=c.id GROUP BY c.id ORDER BY c.created_at DESC").fetchall()
    conn.close()
    return render_template('admin_companies.html', companies=companies)

# ── API ──────────────────────────────────────────────────────────
@app.route('/api/chart-data')
@login_required
def chart_data():
    conn = get_db(); cid = session.get('company_id')
    q = "SELECT name, quantity, threshold FROM products"
    params = []
    if session['role'] != 'admin':
        q += " WHERE company_id=?"; params.append(cid)
    products = conn.execute(q+" ORDER BY quantity ASC", params).fetchall()
    conn.close()
    return jsonify({
        'labels': [p['name'][:14] for p in products],
        'data':   [p['quantity'] for p in products],
        'colors': ['#ff4d6d' if p['quantity'] < p['threshold'] else '#06d6a0' for p in products]
    })

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
