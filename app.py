import os
import re
import json
import base64
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import requests
from sqlalchemy import event
from sqlalchemy.sql import text
from sqlite3 import Connection as SQLiteConnection

# Load environment variables
load_dotenv()

# Verify environment variables
required_env_vars = ['DARAJA_CONSUMER_KEY', 'DARAJA_CONSUMER_SECRET', 'DARAJA_PASSKEY', 'DARAJA_SHORTCODE', 'CALLBACK_URL']
for var in required_env_vars:
    if not os.getenv(var):
        print(f"Warning: Environment variable {var} is not set in .env file.")

# Flask app configuration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secure_secret_key')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'nahidahudeif@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'wvaz rend gbhu lblj')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'nahidahudeif@gmail.com')

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'

# Ensure foreign key support in SQLite
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, SQLiteConnection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

# Register the event listener within an application context
with app.app_context():
    event.listens_for(db.engine, "connect")(set_sqlite_pragma)

# Daraja API Configuration
DARAJA_CONSUMER_KEY = os.getenv('DARAJA_CONSUMER_KEY')
DARAJA_CONSUMER_SECRET = os.getenv('DARAJA_CONSUMER_SECRET')
DARAJA_SHORTCODE = os.getenv('DARAJA_SHORTCODE', '174379')
DARAJA_PASSKEY = os.getenv('DARAJA_PASSKEY')
DARAJA_API_BASE_URL = 'https://sandbox.safaricom.co.ke'
CALLBACK_URL = os.getenv('CALLBACK_URL')
USE_MANUAL_PAYLOAD = False

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(100), nullable=False)
    contact_person = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    pickup_location = db.Column(db.String(255), nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    carts = db.relationship('UserCart', backref='user', lazy=True)
    orders = db.relationship('Order', backref='user', lazy=True)
    user_orders = db.relationship('UserOrder', backref='user', lazy=True)
    admin_orders = db.relationship('AdminOrder', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    images = db.Column(db.String(255))
    reorder_level = db.Column(db.Integer, nullable=False, default=10)
    carts = db.relationship('UserCart', backref='product', lazy=True, cascade='all, delete-orphan')
    orders = db.relationship('Order', backref='product', lazy=True, cascade='all, delete-orphan')
    user_orders = db.relationship('UserOrder', backref='product', lazy=True, cascade='all, delete-orphan')
    admin_orders = db.relationship('AdminOrder', backref='product', lazy=True, cascade='all, delete-orphan')
    stock_transactions = db.relationship('StockTransaction', backref='product', lazy=True, cascade='all, delete-orphan')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    products = db.relationship('Product', backref='category', lazy=True)

class UserCart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    ordered_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')
    checkout_request_id = db.Column(db.String(100), nullable=True)
    mpesa_receipt_number = db.Column(db.String(100), nullable=True)

class UserOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    ordered_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='pending')
    pickup_location = db.Column(db.String(255), nullable=True)

class AdminOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ordered_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='pending')
    pickup_location = db.Column(db.String(255), nullable=True)

class StockTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id', ondelete='CASCADE'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    transaction_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    type = db.Column(db.String(20), nullable=False)

# Initialize database
def initialize_database():
    with app.app_context():
        db.create_all()
        with db.engine.connect() as connection:
            schema = connection.execute(text("SELECT sql FROM sqlite_master WHERE type='table' AND name='stock_transaction';")).fetchone()
            print(f"StockTransaction schema: {schema[0] if schema else 'Not created'}")
        
        if not Category.query.first():
            default_categories = ['Electronics', 'Clothing', 'Food']
            for name in default_categories:
                db.session.add(Category(name=name))
            db.session.commit()
        if not StockTransaction.query.first():
            products = Product.query.all()
            for product in products:
                if product.quantity > 0:
                    transaction = StockTransaction(
                        product_id=product.id,
                        quantity=product.quantity,
                        transaction_date=datetime.utcnow(),
                        type='addition'
                    )
                    db.session.add(transaction)
            db.session.commit()
        print("Database tables created.")

initialize_database()

# Daraja access token
def get_daraja_access_token():
    auth_url = f"{DARAJA_API_BASE_URL}/oauth/v1/generate?grant_type=client_credentials"
    auth = base64.b64encode(f"{DARAJA_CONSUMER_KEY}:{DARAJA_CONSUMER_SECRET}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}"}
    try:
        response = requests.get(auth_url, headers=headers, timeout=10)
        response.raise_for_status()
        result = response.json()
        print(f"Access token generated: {result.get('access_token')[:10]}...")
        return result.get("access_token")
    except requests.RequestException as e:
        print(f"Error generating access token: {e}, Response: {response.text if 'response' in locals() else 'No response'}")
        return None

# Generate STK Push password
def generate_stk_password():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    data = f"{DARAJA_SHORTCODE}{DARAJA_PASSKEY}{timestamp}"
    return base64.b64encode(data.encode()).decode(), timestamp

# Check and notify low stock
def check_and_notify_low_stock():
    low_stock_products = Product.query.filter(Product.quantity <= Product.reorder_level).all()
    if low_stock_products:
        try:
            html_body = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Low Stock Alert</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
                    .container { max-width: 600px; margin: 20px auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                    .header { background: #007bff; color: #fff; padding: 15px; text-align: center; border-radius: 8px 8px 0 0; }
                    .header h1 { margin: 0; font-size: 24px; }
                    .content { padding: 20px; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                    th { background: #f8f9fa; font-weight: bold; }
                    tr:hover { background: #f1f1f1; }
                    .status-depleted { color: #dc3545; font-weight: bold; }
                    .status-low { color: #ffc107; font-weight: bold; }
                    .footer { text-align: center; padding: 10px; font-size: 12px; color: #777; margin-top: 20px; }
                    @media (max-width: 600px) { .container { padding: 10px; } table, th, td { font-size: 14px; } }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header"><h1>Low Stock Alert</h1></div>
                    <div class="content">
                        <p>Dear Admin,</p>
                        <p>The following products have reached or fallen below their re-order levels and require restocking:</p>
                        <table>
                            <thead><tr><th>Product</th><th>Category</th><th>Quantity</th><th>Re-order Level</th><th>Status</th></tr></thead>
                            <tbody>
            """
            for p in low_stock_products:
                status = "Depleted" if p.quantity == 0 else "Low"
                status_class = "status-depleted" if p.quantity == 0 else "status-low"
                html_body += f"""
                                <tr>
                                    <td>{p.name}</td>
                                    <td>{p.category.name}</td>
                                    <td>{p.quantity}</td>
                                    <td>{p.reorder_level}</td>
                                    <td class="{status_class}">{status}</td>
                                </tr>
                """
            html_body += """
                            </tbody>
                        </table>
                        <p>Please take appropriate action to restock these products to avoid stockouts.</p>
                        <p>Best regards,<br>Your Inventory Management System</p>
                    </div>
                    <div class="footer">This is an automated message. Please do not reply directly to this email.</div>
                </div>
            </body>
            </html>
            """
            msg = Message(
                subject="Re-order Level Alert: Restock Required",
                recipients=[os.getenv('ADMIN_EMAIL', 'ramlaabdisitar@gmail.com')],
                html=html_body
            )
            mail.send(msg)
            print(f"Low stock notification sent for {len(low_stock_products)} products.")
            return low_stock_products, True
        except Exception as e:
            print(f"Error sending low stock email: {str(e)}")
            return low_stock_products, False
    return [], False

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Utility function for file uploads
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Routes
@app.route('/')
def home():
    try:
        categories = Category.query.all()
        products = Product.query.all()
    except Exception as e:
        print(f"Database error: {str(e)}")
        categories = []
        products = []
        flash('Database error: Unable to load categories or products.', 'danger')
    cart_items = []
    orders = []
    cart_total = 0
    if current_user.is_authenticated:
        cart_items = UserCart.query.filter_by(user_id=current_user.id).all()
        orders = Order.query.filter_by(user_id=current_user.id).all()
        cart_total = sum(cart_item.product.price * cart_item.quantity for cart_item in cart_items)
    if not products:
        flash('No products available.', 'danger')
    return render_template('home.html', categories=categories, products=products, cart_items=cart_items, orders=orders, cart_total=cart_total, selected_category=None, sort=None, min_price=None, max_price=None, query=None)

@app.route('/profile')
@login_required
def profile():
    cart_items = UserCart.query.filter_by(user_id=current_user.id).all()
    cart_total = sum(item.product.price * item.quantity for item in cart_items)
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.ordered_at.desc()).all()
    pending_orders = Order.query.filter_by(user_id=current_user.id, status='pending').all()
    print(f"Profile loaded: {len(orders)} orders, {len(pending_orders)} pending orders, cart_total={cart_total}")
    return render_template('profile.html', cart_items=cart_items, cart_total=cart_total, orders=orders, pending_orders=pending_orders)

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        current_user.company_name = request.form['company_name']
        current_user.contact_person = request.form['contact_person']
        current_user.email = request.form['email']
        current_user.phone = request.form['phone']
        current_user.address = request.form['address']
        existing_user = User.query.filter(User.email == current_user.email, User.id != current_user.id).first()
        if existing_user:
            flash('Email already in use.', 'danger')
            return redirect(url_for('update_profile'))
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))
    return render_template('update_profile.html', user=current_user)

@app.route('/validate_password', methods=['POST'])
def validate_password():
    try:
        data = request.get_json()
        password = data.get('password', '').strip()
        confirm_password = data.get('confirmPassword', '').strip()
        password_errors = []
        is_password_valid = True
        if len(password) < 8:
            password_errors.append('At least 8 characters required')
            is_password_valid = False
        if not re.search(r'[A-Z]', password):
            password_errors.append('At least one uppercase letter required')
            is_password_valid = False
        if not re.search(r'[a-z]', password):
            password_errors.append('At least one lowercase letter required')
            is_password_valid = False
        if not re.search(r'\d', password):
            password_errors.append('At least one digit required')
            is_password_valid = False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            password_errors.append('At least one special character required')
            is_password_valid = False
        passwords_match = password == confirm_password and password != ''
        return jsonify({
            'isPasswordValid': is_password_valid,
            'passwordErrors': password_errors,
            'passwordsMatch': passwords_match
        })
    except Exception as e:
        print(f"Error in validate_password: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/register', methods=['POST'])
def register():
    company_name = request.form['companyName']
    contact_person = request.form['contactPerson']
    email = request.form['email']
    phone = request.form['phone']
    address = request.form['address']
    password = request.form['password'].strip()
    confirm_password = request.form['confirmPassword'].strip()
    if password != confirm_password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('home'))
    if len(password) < 8:
        flash('Password must be at least 8 characters long.', 'danger')
        return redirect(url_for('home'))
    if not re.search(r'[A-Z]', password):
        flash('Password must contain at least one uppercase letter.', 'danger')
        return redirect(url_for('home'))
    if not re.search(r'[a-z]', password):
        flash('Password must contain at least one lowercase letter.', 'danger')
        return redirect(url_for('home'))
    if not re.search(r'\d', password):
        flash('Password must contain at least one digit.', 'danger')
        return redirect(url_for('home'))
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        flash('Password must contain at least one special character.', 'danger')
        return redirect(url_for('home'))
    if User.query.filter_by(email=email).first():
        flash('Email already exists.', 'danger')
        return redirect(url_for('home'))
    new_user = User(company_name=company_name, contact_person=contact_person, email=email, phone=phone, address=address)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash('Registration successful. Please login.', 'success')
    return redirect(url_for('home'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        login_user(user)
        flash('Login successful.', 'success')
        return redirect(url_for('home'))
    flash('Invalid email or password.', 'danger')
    return redirect(url_for('home'))

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/admin/login', methods=['POST'])
def admin_login():
    username = request.form['admin_username']
    password = request.form['admin_password']
    if username == 'admin' and password == 'admin':
        session['admin_logged_in'] = True
        flash('Admin login successful.', 'success')
        return redirect(url_for('admin_portal'))
    flash('Invalid admin credentials.', 'danger')
    return redirect(url_for('home'))

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Admin logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/admin/blahxyz')
def admin_portal():
    if not session.get('admin_logged_in'):
        flash('Please log in as admin.', 'danger')
        return redirect(url_for('home'))
    categories = Category.query.all()
    orders = AdminOrder.query.all()
    users = User.query.all()
    products = Product.query.all()
    total_sales = db.session.query(db.func.sum(AdminOrder.total_price)).filter(AdminOrder.status == 'delivered').scalar() or 0
    return render_template('admin_portal.html', categories=categories, orders=orders, users=users, products=products, total_sales=total_sales)

@app.route('/admin/add-category', methods=['POST'])
def add_category():
    if not session.get('admin_logged_in'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('home'))
    name = request.form['name']
    if Category.query.filter_by(name=name).first():
        flash('Category already exists.', 'danger')
        return redirect(url_for('admin_portal'))
    new_category = Category(name=name)
    db.session.add(new_category)
    db.session.commit()
    flash('Category added successfully.', 'success')
    return redirect(url_for('admin_portal'))

@app.route('/admin/delete-category/<int:category_id>', methods=['POST'])
def delete_category(category_id):
    if not session.get('admin_logged_in'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('home'))
    category = Category.query.get_or_404(category_id)
    if Product.query.filter_by(category_id=category_id).first():
        flash('Cannot delete category with associated products.', 'danger')
        return redirect(url_for('admin_portal'))
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted successfully.', 'success')
    return redirect(url_for('admin_portal'))

@app.route('/admin/add-product', methods=['POST'])
def admin_add_product():
    if not session.get('admin_logged_in'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('home'))
    uploaded_file_paths = []
    if 'images[]' in request.files:
        files = request.files.getlist('images[]')
        for file in files:
            if file.filename != '':
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    uploaded_file_paths.append(filename)
                else:
                    flash('Invalid file extension.', 'danger')
                    return redirect(url_for('admin_portal'))
    category_id = request.form['category']
    name = request.form['name']
    quantity = int(request.form['quantity'])
    description = request.form['description']
    price = float(request.form['unit_price'])
    reorder_level = int(request.form['reorder_level'])
    new_product = Product(
        name=name,
        category_id=category_id,
        quantity=quantity,
        description=description,
        price=price,
        images=','.join(uploaded_file_paths),
        reorder_level=reorder_level
    )
    db.session.add(new_product)
    db.session.flush()
    if quantity > 0:
        transaction = StockTransaction(
            product_id=new_product.id,
            quantity=quantity,
            transaction_date=datetime.utcnow(),
            type='addition'
        )
        db.session.add(transaction)
    db.session.commit()
    check_and_notify_low_stock()
    flash('Product added successfully.', 'success')
    return redirect(url_for('admin_portal'))

@app.route('/admin/edit-product/<int:product_id>', methods=['POST'])
def edit_product(product_id):
    if not session.get('admin_logged_in'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('home'))
    product = Product.query.get_or_404(product_id)
    try:
        product.name = request.form['name']
        product.category_id = request.form['category']
        old_quantity = product.quantity
        product.quantity = int(request.form['quantity'])
        product.description = request.form['description']
        product.price = float(request.form['unit_price'])
        product.reorder_level = int(request.form['reorder_level'])
        uploaded_file_paths = []
        if 'images[]' in request.files:
            files = request.files.getlist('images[]')
            for file in files:
                if file.filename != '':
                    if allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        uploaded_file_paths.append(filename)
                    else:
                        flash('Invalid file extension.', 'danger')
                        return redirect(url_for('admin_portal'))
            if uploaded_file_paths:
                product.images = ','.join(uploaded_file_paths)
        quantity_diff = product.quantity - old_quantity
        if quantity_diff != 0:
            transaction = StockTransaction(
                product_id=product_id,
                quantity=quantity_diff,
                transaction_date=datetime.utcnow(),
                type='addition' if quantity_diff > 0 else 'deduction'
            )
            db.session.add(transaction)
        db.session.commit()
        check_and_notify_low_stock()
        flash('Product updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error updating product: {str(e)}")
        flash(f'Error updating product: {str(e)}', 'danger')
    return redirect(url_for('admin_portal'))

@app.route('/admin/delete-product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if not session.get('admin_logged_in'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('home'))
    product = Product.query.get_or_404(product_id)
    try:
        if product.user_orders or product.carts or product.orders:
            flash('Cannot delete product with associated orders or cart items.', 'danger')
            return redirect(url_for('admin_portal'))
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting product: {str(e)}")
        flash(f'Error deleting product: {str(e)}', 'danger')
    return redirect(url_for('admin_portal'))

@app.route('/admin/update-order-status/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    if not session.get('admin_logged_in'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('home'))
    try:
        admin_order = AdminOrder.query.get_or_404(order_id)
        new_status = request.form.get('status')
        if new_status not in ['pending', 'delivered', 'canceled']:
            flash(f'Invalid status: {new_status}', 'danger')
            return redirect(url_for('admin_portal'))
        if new_status == 'canceled' and admin_order.status != 'canceled':
            product = Product.query.get(admin_order.product_id)
            product.quantity += admin_order.quantity
            transaction = StockTransaction(
                product_id=admin_order.product_id,
                quantity=admin_order.quantity,
                transaction_date=datetime.utcnow(),
                type='addition'
            )
            db.session.add(transaction)
        admin_order.status = new_status
        user_order = UserOrder.query.filter(
            UserOrder.user_id == admin_order.user_id,
            UserOrder.product_id == admin_order.product_id,
            UserOrder.quantity == admin_order.quantity,
            UserOrder.total_price == admin_order.total_price,
            UserOrder.ordered_at == admin_order.ordered_at
        ).first()
        if user_order:
            user_order.status = new_status
        order = Order.query.filter(
            Order.user_id == admin_order.user_id,
            Order.product_id == admin_order.product_id,
            Order.quantity == admin_order.quantity,
            Order.total_price == admin_order.total_price,
            Order.ordered_at == admin_order.ordered_at
        ).first()
        if order:
            order.status = new_status
        db.session.commit()
        check_and_notify_low_stock()
        flash('Order status updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error updating order status: {str(e)}")
        flash(f'Error updating order status: {str(e)}', 'danger')
    return redirect(url_for('admin_portal'))

@app.route('/cancel-order/<int:order_id>', methods=['POST'])
@login_required
def cancel_order(order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
    if not order:
        flash('Order not found.', 'danger')
        return redirect(url_for('profile'))
    if order.status != 'pending':
        flash('Cannot cancel non-pending order.', 'danger')
        return redirect(url_for('profile'))
    try:
        product = Product.query.get(order.product_id)
        product.quantity += order.quantity
        order.status = 'canceled'
        transaction = StockTransaction(
            product_id=order.product_id,
            quantity=order.quantity,
            transaction_date=datetime.utcnow(),
            type='addition'
        )
        db.session.add(transaction)
        user_order = UserOrder.query.filter(
            UserOrder.user_id == current_user.id,
            UserOrder.product_id == order.product_id,
            UserOrder.quantity == order.quantity,
            UserOrder.total_price == order.total_price,
            UserOrder.ordered_at == order.ordered_at
        ).first()
        if user_order:
            user_order.status = 'canceled'
        admin_order = AdminOrder.query.filter(
            AdminOrder.user_id == current_user.id,
            AdminOrder.product_id == order.product_id,
            AdminOrder.quantity == order.quantity,
            AdminOrder.total_price == order.total_price,
            AdminOrder.ordered_at == order.ordered_at
        ).first()
        if admin_order:
            admin_order.status = 'canceled'
            transaction = StockTransaction(
                product_id=admin_order.product_id,
                quantity=admin_order.quantity,
                transaction_date=datetime.utcnow(),
                type='addition'
            )
            db.session.add(transaction)
        db.session.commit()
        check_and_notify_low_stock()
        flash('Order canceled successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error canceling order: {str(e)}")
        flash(f'Error canceling order: {str(e)}', 'danger')
    return redirect(url_for('profile'))

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('admin_logged_in'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_portal'))

@app.route('/product/<int:product_id>')
def product_details():
    product = Product.query.get_or_404(product_id)
    return render_template('product_details.html', product=product)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    try:
        quantity = int(request.form.get('quantity', 0))
        if quantity <= 0:
            flash('Quantity must be positive.', 'danger')
            return redirect(url_for('home'))
        product = Product.query.get(product_id)
        if not product:
            flash('Product not found.', 'danger')
            return redirect(url_for('home'))
        if quantity > product.quantity:
            flash(f'Only {product.quantity} units available for {product.name}.', 'danger')
            return redirect(url_for('home'))
        cart_item = UserCart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = UserCart(user_id=current_user.id, product_id=product_id, quantity=quantity)
            db.session.add(cart_item)
        db.session.commit()
        flash('Product added to cart successfully.', 'success')
    except ValueError:
        flash('Invalid quantity.', 'danger')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('home'))

@app.route('/update_cart_quantity', methods=['POST'])
@login_required
def update_cart_quantity():
    data = request.get_json()
    product_id = data['product_id']
    new_quantity = data['new_quantity']
    cart_item = UserCart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if cart_item:
        product = Product.query.get(product_id)
        if new_quantity > product.quantity:
            return jsonify({'success': False, 'message': f'Only {product.quantity} units available.'})
        cart_item.quantity = new_quantity
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Cart item not found.'})

@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    cart_item = UserCart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
        flash('Product removed from cart.', 'success')
    else:
        flash('Product not found in cart.', 'danger')
    return redirect(url_for('profile'))

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    transaction_code = request.form['transaction-code']
    if re.match(r'^[Ss]\w{9}$', transaction_code):
        cart_items = UserCart.query.filter_by(user_id=current_user.id).all()
        try:
            ordered_at = datetime.utcnow()
            for cart_item in cart_items:
                product = Product.query.get(cart_item.product_id)
                if product:
                    if cart_item.quantity <= product.quantity:
                        product.quantity -= cart_item.quantity
                        total_price = cart_item.quantity * product.price
                        order = Order(
                            user_id=current_user.id,
                            product_id=product.id,
                            quantity=cart_item.quantity,
                            total_price=total_price,
                            status='pending',
                            ordered_at=ordered_at
                        )
                        db.session.add(order)
                        user_order = UserOrder(
                            user_id=current_user.id,
                            product_id=product.id,
                            quantity=cart_item.quantity,
                            total_price=total_price,
                            pickup_location=current_user.address,
                            ordered_at=ordered_at
                        )
                        db.session.add(user_order)
                        admin_order = AdminOrder(
                            user_id=current_user.id,
                            product_id=product.id,
                            quantity=cart_item.quantity,
                            total_price=total_price,
                            pickup_location=current_user.address,
                            ordered_at=ordered_at
                        )
                        db.session.add(admin_order)
                        transaction = StockTransaction(
                            product_id=admin_order.product_id,
                            quantity=-admin_order.quantity,
                            transaction_date=admin_order.ordered_at,
                            type='order'
                        )
                        db.session.add(transaction)
                        db.session.delete(cart_item)
                    else:
                        flash(f"Not enough quantity for {product.name}.", 'danger')
                        return redirect(url_for('profile'))
            db.session.commit()
            check_and_notify_low_stock()
            flash('Order placed successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            print(f"Error during checkout: {str(e)}")
            flash(f'Checkout failed: {str(e)}', 'danger')
        return redirect(url_for('profile'))
    flash('Invalid transaction code.', 'danger')
    return redirect(url_for('profile'))

@app.route('/initiate_stk_push', methods=['POST'])
@login_required
def initiate_stk_push():
    try:
        phone_number = request.form.get('phone_number')
        amount = float(request.form.get('amount'))
        if not phone_number or not amount:
            return jsonify({"success": False, "message": "Phone number and amount are required"}), 400

        if not re.match(r'^254[7|1][0-9]{8}$', phone_number):
            return jsonify({"success": False, "message": "Invalid phone number format. Use 2547XXXXXXXX or 2541XXXXXXXX"}), 400

        cart_items = UserCart.query.filter_by(user_id=current_user.id).all()
        if not cart_items:
            return jsonify({"success": False, "message": "Cart is empty"}), 400

        total_price = sum(item.product.price * item.quantity for item in cart_items)
        if abs(total_price - amount) > 0.01:
            return jsonify({"success": False, "message": "Amount does not match cart total"}), 400

        consumer_key = os.getenv('DARAJA_CONSUMER_KEY')
        consumer_secret = os.getenv('DARAJA_CONSUMER_SECRET')
        api_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        headers = {"Authorization": "Basic " + base64.b64encode(f"{consumer_key}:{consumer_secret}".encode()).decode()}
        response = requests.get(api_url, headers=headers)
        access_token = response.json().get('access_token')
        if not access_token:
            print(f"Failed to get access token: {response.text}")
            return jsonify({"success": False, "message": "Failed to authenticate with M-Pesa"}), 500

        stk_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        headers = {"Authorization": f"Bearer {access_token}"}
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        passkey = os.getenv('DARAJA_PASSKEY')
        shortcode = os.getenv('DARAJA_SHORTCODE')
        password = base64.b64encode(f"{shortcode}{passkey}{timestamp}".encode()).decode()
        payload = {
            "BusinessShortCode": shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": int(amount),
            "PartyA": phone_number,
            "PartyB": shortcode,
            "PhoneNumber": phone_number,
            "CallBackURL": os.getenv('CALLBACK_URL'),
            "AccountReference": f"Order_{current_user.id}",
            "TransactionDesc": "Payment for order"
        }

        print(f"STK Push request: {json.dumps(payload, indent=4)}")
        response = requests.post(stk_url, json=payload, headers=headers)
        print(f"Daraja API response: {response.text}")

        if response.status_code != 200 or response.json().get('ResponseCode') != '0':
            print(f"STK Push failed: {response.text}")
            return jsonify({"success": False, "message": "Failed to initiate STK Push"}), 500

        checkout_request_id = response.json().get('CheckoutRequestID')
        if not checkout_request_id:
            print(f"STK Push error: No CheckoutRequestID in response: {response.text}")
            return jsonify({"success": False, "message": "No CheckoutRequestID received"}), 500

        order_ids = []
        user_order_ids = []
        admin_order_ids = []
        for item in cart_items:
            order = Order(
                user_id=current_user.id,
                product_id=item.product_id,
                quantity=item.quantity,
                total_price=item.product.price * item.quantity,
                status="pending",
                checkout_request_id=checkout_request_id
            )
            db.session.add(order)
            db.session.flush()
            order_ids.append(order.id)

            user_order = UserOrder(
                user_id=current_user.id,
                product_id=item.product_id,
                quantity=item.quantity,
                total_price=item.product.price * item.quantity,
                status="pending"
            )
            db.session.add(user_order)
            db.session.flush()
            user_order_ids.append(user_order.id)

            admin_order = AdminOrder(
                user_id=current_user.id,
                product_id=item.product_id,
                quantity=item.quantity,
                total_price=item.product.price * item.quantity,
                status="pending"
            )
            db.session.add(admin_order)
            db.session.flush()
            admin_order_ids.append(admin_order.id)

        UserCart.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        print(f"Orders created: Order IDs={order_ids}, UserOrder IDs={user_order_ids}, AdminOrder IDs={admin_order_ids}")

        return jsonify({"success": True, "message": "STK Push sent to your phone. Please complete the payment."}), 200

    except Exception as e:
        db.session.rollback()
        print(f"STK Push error: {str(e)}")
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500

@app.route('/mpesa/callback', methods=['POST'])
def mpesa_callback():
    try:
        # Log raw request data
        raw_data = request.get_data(as_text=True)
        print(f"Callback raw data at {datetime.utcnow()}: {raw_data}")

        # Parse JSON data
        data = request.get_json(silent=True)
        if not data:
            print(f"Callback error: Invalid or missing JSON data: {raw_data}")
            return jsonify({"ResultCode": 1, "ResultDesc": "Invalid or missing JSON data"}), 400

        # Log parsed JSON
        print(f"Callback parsed JSON at {datetime.utcnow()}: {json.dumps(data, indent=4)}")

        # Extract STK callback details
        stk_callback = data.get("Body", {}).get("stkCallback", {})
        if not stk_callback:
            print("Callback error: Missing stkCallback in Body")
            return jsonify({"ResultCode": 1, "ResultDesc": "Missing stkCallback in Body"}), 400

        result_code = stk_callback.get("ResultCode")
        result_desc = stk_callback.get("ResultDesc", "No description provided")
        checkout_request_id = stk_callback.get("CheckoutRequestID")

        if not checkout_request_id:
            print("Callback error: Missing CheckoutRequestID")
            return jsonify({"ResultCode": 1, "ResultDesc": "Missing CheckoutRequestID"}), 400

        # Log all orders
        all_orders = Order.query.all()
        print(f"All orders in database: {[o.id for o in all_orders]}, "
              f"CheckoutRequestIDs: {[o.checkout_request_id for o in all_orders]}")

        # Find orders
        orders = Order.query.filter_by(checkout_request_id=checkout_request_id).all()
        if not orders:
            print(f"Callback error: No orders found for CheckoutRequestID {checkout_request_id}")
            return jsonify({"ResultCode": 1, "ResultDesc": f"No orders found for CheckoutRequestID {checkout_request_id}"}), 404

        if result_code == 0:
            # Extract M-Pesa receipt number
            mpesa_receipt = None
            callback_metadata = stk_callback.get("CallbackMetadata", {}).get("Item", [])
            for item in callback_metadata:
                if item.get("Name") == "MpesaReceiptNumber":
                    mpesa_receipt = item.get("Value")
                    break

            # Update orders
            updated_order_ids = []
            updated_user_order_ids = []
            updated_admin_order_ids = []
            for order in orders:
                order.status = "completed"
                order.mpesa_receipt_number = mpesa_receipt
                updated_order_ids.append(order.id)

                user_order = UserOrder.query.filter(
                    UserOrder.user_id == order.user_id,
                    UserOrder.product_id == order.product_id,
                    UserOrder.quantity == order.quantity,
                    UserOrder.total_price == order.total_price,
                    UserOrder.ordered_at == order.ordered_at
                ).first()
                if user_order:
                    user_order.status = "completed"
                    updated_user_order_ids.append(user_order.id)

                admin_order = AdminOrder.query.filter(
                    AdminOrder.user_id == order.user_id,
                    AdminOrder.product_id == order.product_id,
                    AdminOrder.quantity == order.quantity,
                    AdminOrder.total_price == order.total_price,
                    AdminOrder.ordered_at == order.ordered_at
                ).first()
                if admin_order:
                    admin_order.status = "completed"
                    updated_admin_order_ids.append(admin_order.id)

            db.session.commit()
            print(f"Callback processed successfully: checkout_request_id={checkout_request_id}, "
                  f"orders_updated={updated_order_ids}, "
                  f"user_orders_updated={updated_user_order_ids}, "
                  f"admin_orders_updated={updated_admin_order_ids}")

            check_and_notify_low_stock()
            return jsonify({"ResultCode": 0, "ResultDesc": "Success"}), 200
        else:
            print(f"Callback failed: ResultCode={result_code}, ResultDesc={result_desc}")
            return jsonify({"ResultCode": 1, "ResultDesc": f"Payment failed: {result_desc}"}), 400

    except Exception as e:
        db.session.rollback()
        print(f"Callback error at {datetime.utcnow()}: {str(e)}, Raw data: {raw_data}")
        return jsonify({"ResultCode": 1, "ResultDesc": f"Server error: {str(e)}"}), 500
    
@app.route('/debug', methods=['GET', 'POST', 'PUT', 'DELETE'])
def debug():
    raw_data = request.get_data(as_text=True)
    print(f"Debug request at {datetime.utcnow()}: Method={request.method}, Path={request.path}, "
          f"Headers={dict(request.headers)}, Body={raw_data}")
    return jsonify({"received": True, "method": request.method, "path": request.path, "body": raw_data}), 200
  
@app.route('/check_order_status', methods=['GET'])
@login_required
def check_order_status():
    try:
        recent_time = datetime.utcnow() - timedelta(minutes=10)  # Look back 10 minutes
        completed_orders = Order.query.filter(
            Order.user_id == current_user.id,
            Order.status == 'completed',
            Order.ordered_at >= recent_time
        ).first()
        return jsonify({"completed": bool(completed_orders)})
    except Exception as e:
        print(f"Error checking order status: {str(e)}")
        return jsonify({"completed": False, "error": str(e)}), 500
    
@app.route('/get_orders', methods=['GET'])
@login_required
def get_orders():
    try:
        orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.ordered_at.desc()).all()
        orders_data = [
            {
                'id': order.id,
                'product_name': order.product.name,
                'quantity': order.quantity,
                'total_price': order.total_price,
                'ordered_at': order.ordered_at.isoformat(),
                'status': order.status,
                'mpesa_receipt_number': order.mpesa_receipt_number
            }
            for order in orders
        ]
        return jsonify({'orders': orders_data})
    except Exception as e:
        print(f"Error fetching orders: {str(e)}")
        return jsonify({'error': 'Failed to fetch orders'}), 500
    
    
@app.route('/verify_payment', methods=['POST'])
@login_required
def verify_payment():
    order_id = request.form.get("order_id")
    mpesa_receipt = request.form.get("mpesa_receipt")
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('profile'))
    if not mpesa_receipt:
        flash("Please enter a valid M-Pesa receipt number.", "danger")
        return redirect(url_for('profile'))
    try:
        order.status = "completed"
        order.mpesa_receipt_number = mpesa_receipt
        user_order = UserOrder.query.filter(
            UserOrder.user_id == order.user_id,
            UserOrder.product_id == order.product_id,
            UserOrder.quantity == order.quantity,
            UserOrder.total_price == order.total_price,
            UserOrder.ordered_at == order.ordered_at
        ).first()
        if user_order:
            user_order.status = "completed"
        admin_order = AdminOrder.query.filter(
            AdminOrder.user_id == order.user_id,
            AdminOrder.product_id == order.product_id,
            AdminOrder.quantity == order.quantity,
            AdminOrder.total_price == order.total_price,
            AdminOrder.ordered_at == order.ordered_at
        ).first()
        if admin_order:
            admin_order.status = "completed"
        UserCart.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        print(f"Payment verified: order_id={order_id}, mpesa_receipt={mpesa_receipt}")
        check_and_notify_low_stock()
        flash("Payment verified successfully.", "success")
    except Exception as e:
        db.session.rollback()
        print(f"Error verifying payment: {str(e)}")
        flash(f"Error verifying payment: {str(e)}", "danger")
    return redirect(url_for('profile'))

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()
    category_id = request.args.get('category_id', type=int)
    sort = request.args.get('sort', '')
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    products_query = Product.query
    if query:
        products_query = products_query.filter(Product.name.ilike(f"%{query}%"))
    if category_id:
        products_query = products_query.filter_by(category_id=category_id)
    if min_price is not None:
        products_query = products_query.filter(Product.price >= min_price)
    if max_price is not None:
        products_query = products_query.filter(Product.price <= max_price)
    if sort == 'price_asc':
        products_query = products_query.order_by(Product.price.asc())
    elif sort == 'price_desc':
        products_query = products_query.order_by(Product.price.desc())
    products = products_query.all()
    categories = Category.query.all()
    cart_items = []
    orders = []
    cart_total = 0
    if current_user.is_authenticated:
        cart_items = UserCart.query.filter_by(user_id=current_user.id).all()
        orders = Order.query.filter_by(user_id=current_user.id).all()
        cart_total = sum(cart_item.product.price * cart_item.quantity for cart_item in cart_items)
    if not products and (query or category_id or min_price or max_price):
        flash('No products match your criteria.', 'danger')
    return render_template(
        'home.html',
        categories=categories,
        products=products,
        cart_items=cart_items,
        orders=orders,
        cart_total=cart_total,
        selected_category=category_id,
        sort=sort,
        min_price=min_price,
        max_price=max_price,
        query=query
    )

@app.route('/admin/reports/reorder_level', methods=['GET', 'POST'])
def reorder_level_report():
    if not session.get('admin_logged_in'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('home'))
    low_stock_products = Product.query.filter(Product.quantity <= Product.reorder_level).all()
    if request.method == 'POST':
        products, success = check_and_notify_low_stock()
        if success:
            flash('Re-order level email sent successfully.', 'success')
        elif products:
            flash('Failed to send re-order level email.', 'danger')
        else:
            flash('No products need restocking.', 'info')
        return redirect(url_for('reorder_level_report'))
    return render_template('reorder_level_report.html', products=low_stock_products)

@app.route('/admin/reports/stock_calendar', methods=['GET'])
def stock_calendar_report():
    if not session.get('admin_logged_in'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('home'))
    selected_date_str = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
    try:
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d')
    except ValueError:
        selected_date = datetime.now()
    selected_date = selected_date.replace(hour=23, minute=59, second=59, microsecond=999999)
    selected_date_utc = selected_date.astimezone(timezone(timedelta(hours=3))).astimezone(timezone.utc)
    stock_query = db.session.query(
        Product.id,
        Product.name,
        Category.name.label('category_name'),
        db.func.coalesce(db.func.sum(StockTransaction.quantity), 0).label('estimated_stock')
    ).join(Category, Product.category_id == Category.id)\
     .outerjoin(StockTransaction, 
                (StockTransaction.product_id == Product.id) & 
                (StockTransaction.transaction_date <= selected_date_utc))\
     .group_by(Product.id, Product.name, Category.name)\
     .all()
    stock_data = [
        {
            'product': {
                'id': item.id,
                'name': item.name,
                'category': {'name': item.category_name}
            },
            'estimated_stock': max(item.estimated_stock, 0)
        }
        for item in stock_query
    ]
    print(f"Stock data for {selected_date_str}:", 
          [(item['product']['id'], item['product']['name'], item['estimated_stock']) for item in stock_data])
    return render_template('stock_calendar_report.html', stock_data=stock_data, selected_date=selected_date)

@app.route('/admin/reports/product_movement')
def product_movement_report():
    if not session.get('admin_logged_in'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('home'))
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    all_orders = AdminOrder.query.filter(
        AdminOrder.ordered_at >= thirty_days_ago,
        AdminOrder.status != 'canceled'
    ).all()
    print("All AdminOrder records (last 30 days, non-canceled):", 
          [(o.id, o.product_id, o.ordered_at, o.status) for o in all_orders])
    product_orders = db.session.query(
        Product.id,
        Product.name,
        Product.category_id,
        Category.name.label('category_name'),
        db.func.count(AdminOrder.id).label('num_orders')
    ).join(AdminOrder).join(Category, Product.category_id == Category.id).filter(
        AdminOrder.ordered_at >= thirty_days_ago,
        AdminOrder.status != 'canceled'
    ).group_by(Product.id, Category.name).having(
        db.func.count(AdminOrder.id) > 1
    ).all()
    print("Products with >1 order:", [(p.id, p.name, p.num_orders, p.category_name) for p in product_orders])
    if not product_orders:
        product_orders = db.session.query(
            Product.id,
            Product.name,
            Product.category_id,
            Category.name.label('category_name'),
            db.func.count(AdminOrder.id).label('num_orders')
        ).join(AdminOrder).join(Category, Product.category_id == Category.id).filter(
            AdminOrder.ordered_at >= thirty_days_ago,
            AdminOrder.status != 'canceled'
        ).group_by(Product.id, Category.name).all()
        print("All products with orders:", [(p.id, p.name, p.num_orders, p.category_name) for p in product_orders])
    fast_moving = sorted(product_orders, key=lambda x: x.num_orders or 0, reverse=True)[:5]
    slow_moving = sorted([p for p in product_orders if p.num_orders], key=lambda x: x.num_orders)[:5]
    return render_template('product_movement_report.html', fast_moving=fast_moving, slow_moving=slow_moving)

@app.route('/admin/reports/order_status')
def order_status_report():
    if not session.get('admin_logged_in'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('home'))
    pending_orders = AdminOrder.query.filter_by(status='pending').all()
    delivered_orders = AdminOrder.query.filter_by(status='delivered').all()
    canceled_orders = AdminOrder.query.filter_by(status='canceled').all()
    return render_template('order_status_report.html', 
                         pending_orders=pending_orders, 
                         delivered_orders=delivered_orders, 
                         canceled_orders=canceled_orders)

@app.route('/test_access_token')
def test_access_token():
    token = get_daraja_access_token()
    return jsonify({"access_token": token, "status": "success" if token else "failed"})

if __name__ == '__main__':
    app.run(debug=True)