from flask import Flask, render_template, request, redirect, url_for
from flask import Flask, render_template, request, redirect, session
from encryption import encrypt_card, decrypt_card, generate_token   # <-- import functions
from encryption import decrypt_card  # use your helper function
import mysql.connector
import hashlib
import binascii
import secrets
from config import DB_CONFIG
from flask import session

app = Flask(__name__)
app.secret_key = "super_secret_flask_key_123"  # change in production
def verify_user(username, password):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        # convert salt from binary to hex
        salt_hex = binascii.hexlify(user['salt']).decode()
        # hash = SHA256(hex(salt) + password)
        to_hash = (salt_hex + password).encode('utf-8')
        pwd_hash = hashlib.sha256(to_hash).hexdigest()
        if pwd_hash == user['password_hash']:
            return user
    return None
@app.before_request
def require_login():
    allowed_routes = ["login", "static"]
    if request.endpoint not in allowed_routes and "user_id" not in session:
        return redirect("/")

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form['username']
        input_password = request.form['password']

        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            return render_template("login.html", message="Invalid username or password")

        # Fetch salt (stored as BLOB) and convert to hex
        salt = user['salt']              # binary from DB
        hex_salt = binascii.hexlify(salt).decode()

        # Hash input password with salt
        pwd_hash = hashlib.sha256((hex_salt + input_password).encode('utf-8')).hexdigest()

        if pwd_hash == user['password_hash']:
            # Login successful
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role_id'] = user['role_id']

            # Redirect based on role
            role_redirect = {
                1: '/admin/dashboard',     # Admin
                2: '/billing/dashboard',   # Billing
                3: '/support/dashboard',   # Support
                4: '/auditor/dashboard'    # Auditor
            }

            return redirect(role_redirect.get(user['role_id'], '/'))

        else:
            return render_template("login.html", message="Invalid username or password")

    return render_template("login.html")
def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",   # Leave empty for XAMPP default
        database="card_vault_db"  # use the name of your DB
    )
@app.route("/dashboard/<int:role>")
def dashboard(role):
    if role == 1:
        return render_template("admindash.html")
    elif role == 2:
        return render_template("billingdash.html")
    elif role == 3:
        return render_template("support.html")
    else:
        return "<h2>Unauthorized role</h2>"
@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template("admindash.html")


@app.route('/admin/create_user', methods=['GET', 'POST'])
def admin_create_user():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT role_id, role_name FROM roles")
    roles = cursor.fetchall()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role_id = request.form['role_id']

        # 1. Generate random salt (32 bytes → 64 hex chars)
        salt = secrets.token_hex(32)

        # 2. Hash password + salt
        salted_hash = hashlib.sha256((password + salt).encode()).hexdigest()

        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt, role_id) VALUES (%s, %s, %s, %s)",
                (username, salted_hash, salt, role_id)
            )
            conn.commit()
            return render_template("admincreateuser.html", roles=roles,
                                   message="User created successfully!")

        except Exception as e:
            return render_template("admincreateuser.html", roles=roles,
                                   message="Error: " + str(e))

    return render_template("admincreateuser.html", roles=roles)

@app.route('/admin/users')
def admin_view_users():
    conn = get_db()
    cursor = conn.cursor()

    # Fetch users & roles
    cursor.execute("""
        SELECT u.user_id, u.username, r.role_name
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        ORDER BY u.user_id ASC
    """)
    
    users = cursor.fetchall()
    return render_template("adminviewusers.html", users=users)

@app.route('/admin/delete_user/<int:user_id>')
def admin_delete_user(user_id):
    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM users WHERE user_id=%s", (user_id,))
        conn.commit()
        return redirect("/admin/users")
    except Exception as e:
        return f"Error deleting user: {e}"
@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    conn = get_db()
    cursor = conn.cursor()

    # Fetch the user details
    cursor.execute("""
        SELECT u.user_id, u.username, r.role_name, u.role_id
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        WHERE u.user_id = %s
    """, (user_id,))
    user = cursor.fetchone()

    # Fetch all roles for dropdown
    cursor.execute("SELECT role_id, role_name FROM roles")
    roles = cursor.fetchall()

    if request.method == 'POST':
        new_role = request.form['role_id']
        cursor.execute("UPDATE users SET role_id = %s WHERE user_id = %s", (new_role, user_id))
        conn.commit()

        # Re-fetch updated user
        cursor.execute("""
            SELECT u.user_id, u.username, r.role_name, u.role_id
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            WHERE u.user_id = %s
        """, (user_id,))
        user = cursor.fetchone()

        return render_template(
            "adminedituser.html",
            user=user,
            roles=roles,
            message="Role updated successfully!"
        )

    return render_template("adminedituser.html", user=user, roles=roles)
@app.route('/billing/dashboard')
def billing_dashboard():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # Fetch all customers
    cursor.execute("SELECT customer_id, first_name FROM customers")
    customers = cursor.fetchall()

    # Fetch stored cards for each customer
    for customer in customers:
        cursor.execute("SELECT last4, card_type FROM cards WHERE customer_id = %s", (customer['customer_id'],))
        cards = cursor.fetchall()
        customer['cards'] = cards  # add a 'cards' key to each customer

    # Count total cards
    cursor.execute("SELECT COUNT(*) AS total_cards FROM cards")
    total_cards = cursor.fetchone()['total_cards']

    return render_template("billingdash.html",
                           customers=customers,
                           total_cards=total_cards)

@app.route('/billing/add_card', methods=['GET', 'POST'])
def billing_add_card():
    conn = get_db()
    cursor = conn.cursor()

    # Load customers for dropdown
    cursor.execute("SELECT customer_id, first_name FROM customers")
    customers = cursor.fetchall()

    if request.method == 'POST':
        customer_id = request.form['customer_id']
        cardholder_name = request.form['cardholder_name']
        card_type = request.form['card_type']
        card_number = request.form['card_number']
        expiry_month = request.form['expiry_month']
        expiry_year = request.form['expiry_year']

        # Encrypt PAN and generate token
        pan_encrypted = encrypt_card(card_number)
        pan_token = generate_token()
        last4 = card_number[-4:]

        try:
            cursor.execute("""
                INSERT INTO cards
                (customer_id, cardholder_name, card_type, last4, expiry_month, expiry_year, pan_encrypted, pan_token)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (customer_id, cardholder_name, card_type, last4, expiry_month, expiry_year, pan_encrypted, pan_token))
            conn.commit()
            return render_template("billingaddcard.html", customers=customers,
                                   message="Card stored successfully!")

        except Exception as e:
            return render_template("billingaddcard.html", customers=customers,
                                   message=f"Error: {e}")

    return render_template("billingaddcard.html", customers=customers)

@app.route('/billing/invoice', methods=['GET', 'POST'])
def billing_invoice():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # Load customers for dropdown (using correct column names)
    cursor.execute("""
        SELECT DISTINCT customer_id, cardholder_name
        FROM cards
    """)
    customers = cursor.fetchall()

    card_info = None
    amount = None

    if request.method == 'POST':
        # SAFER: avoid KeyError
        customer_id = request.form.get('customer_id')
        amount = request.form.get('amount')

        if not customer_id:
            message = "Please select a customer."
            return render_template("billinginvoice.html",
                                   customers=customers,
                                   message=message)

        # Fetch stored card for selected customer
        cursor.execute("""
            SELECT cardholder_name, card_type, last4, expiry_month, expiry_year, pan_encrypted
            FROM cards
            WHERE customer_id = %s
            ORDER BY created_at ASC
            LIMIT 1
        """, (customer_id,))

        card = cursor.fetchone()
        if card:
            decrypted_pan = decrypt_card(card['pan_encrypted'])

            card_info = {
                'cardholder_name': card['cardholder_name'],
                'card_type': card['card_type'],
                'last4': card['last4'],
                'expiry_month': card['expiry_month'],
                'expiry_year': card['expiry_year'],
                'pan': decrypted_pan
            }

            message = "Invoice created successfully! (Payment simulated)"
            return render_template("billinginvoice.html",
                                   customers=customers,
                                   card=card_info,
                                   amount=amount,
                                   message=message)
        else:
            message = "No stored card found for this customer!"
            return render_template("billinginvoice.html",
                                   customers=customers,
                                   message=message)

    return render_template("billinginvoice.html", customers=customers)

if __name__ == "__main__":
    app.run(debug=True)
