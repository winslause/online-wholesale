import os
import re
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import uuid

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)

# Define User model
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
    orders = db.relationship('UserOrder', backref='user', lazy=True)
    admin_orders = db.relationship('AdminOrder', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Define Product model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    images = db.Column(db.String(255))
    user_orders = db.relationship('UserOrder', backref='product', lazy=True)
    admin_orders = db.relationship('AdminOrder', backref='product', lazy=True)

# Define Category model
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    products = db.relationship('Product', backref='category', lazy=True)

# Define UserCart model
class UserCart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    product = relationship('Product', backref='carts')

# Define UserOrder model
class UserOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    ordered_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='pending')
    pickup_location = db.Column(db.String(255), nullable=True)

# Define AdminOrder model
class AdminOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ordered_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='pending')
    pickup_location = db.Column(db.String(255), nullable=True)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Admin authentication
@app.route('/admin/login', methods=['POST'])
def admin_login():
    username = request.form['admin_username']
    password = request.form['admin_password']
    print(f"Admin login endpoint: username='{username}', password='[HIDDEN]'")
    if username == 'admin' and password == 'admin':
        session['admin_logged_in'] = True
        flash('Admin login successful.')
        return redirect(url_for('admin_portal'))
    flash('Invalid admin credentials.')
    return redirect(url_for('home'))

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Admin logged out.')
    return redirect(url_for('home'))

# Home page
@app.route('/')
def home():
    categories = Category.query.all()
    products = Product.query.all()
    cart_items = []
    orders = []
    cart_total = 0
    if current_user.is_authenticated:
        cart_items = UserCart.query.filter_by(user_id=current_user.id).all()
        orders = UserOrder.query.filter_by(user_id=current_user.id).all()
        cart_total = sum(cart_item.product.price * cart_item.quantity for cart_item in cart_items)
        print(f"Home route: Loaded {len(cart_items)} cart items and {len(orders)} orders for user {current_user.id}, cart_total={cart_total}")
    if not products:
        flash('No products available.')
    return render_template('home.html', categories=categories, products=products, cart_items=cart_items, orders=orders, cart_total=cart_total)

# Profile page
@app.route('/profile')
@login_required
def profile():
    cart_items = UserCart.query.filter_by(user_id=current_user.id).all()
    orders = UserOrder.query.filter_by(user_id=current_user.id).all()
    cart_total = sum(cart_item.product.price * cart_item.quantity for cart_item in cart_items)
    print(f"Profile route: Loaded {len(cart_items)} cart items and {len(orders)} orders for user {current_user.id}, cart_total={cart_total}")
    return render_template('profile.html', cart_items=cart_items, orders=orders, cart_total=cart_total)

# Update profile
@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        current_user.company_name = request.form['company_name']
        current_user.contact_person = request.form['contact_person']
        current_user.email = request.form['email']
        current_user.phone = request.form['phone']
        current_user.address = request.form['address']
        current_user.pickup_location = request.form['pickup_location']
        
        # Validate email uniqueness
        existing_user = User.query.filter(User.email == current_user.email, User.id != current_user.id).first()
        if existing_user:
            flash('Email already in use by another user.')
            return redirect(url_for('update_profile'))
        
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))
    
    return render_template('update_profile.html', user=current_user)

# Password validation endpoint
@app.route('/validate_password', methods=['POST'])
def validate_password():
    try:
        data = request.get_json()
        password = data.get('password', '').strip()
        confirm_password = data.get('confirmPassword', '').strip()

        print(f"Validate_password endpoint: password='{password}', confirm_password='{confirm_password}', "
              f"password_length={len(password)}, confirm_password_length={len(confirm_password)}")

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
            password_errors.append('At least one number required')
            is_password_valid = False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            password_errors.append('At least one special character required')
            is_password_valid = False

        passwords_match = password == confirm_password and password != ''

        response = {
            'isPasswordValid': is_password_valid,
            'passwordErrors': password_errors,
            'passwordsMatch': passwords_match
        }

        print('Validate_password response:', response)
        return jsonify(response)
    except Exception as e:
        print(f"Error in validate_password: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

# Registration
@app.route('/register', methods=['POST'])
def register():
    company_name = request.form['companyName']
    contact_person = request.form['contactPerson']
    email = request.form['email']
    phone = request.form['phone']
    address = request.form['address']
    password = request.form['password'].strip()
    confirm_password = request.form['confirmPassword'].strip()

    print(f"Register endpoint: password='{password}', confirm_password='{confirm_password}', "
          f"password_length={len(password)}, confirm_password_length={len(confirm_password)}")

    # Server-side password validation
    if password != confirm_password:
        flash('Passwords do not match.')
        return redirect(url_for('home'))

    # Password strength validation
    if len(password) < 8:
        flash('Password must be at least 8 characters long.')
        return redirect(url_for('home'))
    if not re.search(r'[A-Z]', password):
        flash('Password must contain at least one uppercase letter.')
        return redirect(url_for('home'))
    if not re.search(r'[a-z]', password):
        flash('Password must contain at least one lowercase letter.')
        return redirect(url_for('home'))
    if not re.search(r'\d', password):
        flash('Password must contain at least one number.')
        return redirect(url_for('home'))
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        flash('Password must contain at least one special character.')
        return redirect(url_for('home'))

    if User.query.filter_by(email=email).first():
        flash('Email already exists.')
        return redirect(url_for('home'))

    new_user = User(company_name=company_name, contact_person=contact_person, email=email, phone=phone, address=address)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash('Registration successful. Please login.', 'success')
    return redirect(url_for('home'))

# User login
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    print(f"Login endpoint: email='{email}', password='[HIDDEN]', password_length={len(password)}")
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        login_user(user)
        print(f"Login successful for user: {email}")
        flash('Login successful.', 'success')
        return redirect(url_for('home'))
    print(f"Login failed for email: {email}")
    flash('Invalid email or password.')
    return redirect(url_for('home'))

# User logout
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# Admin portal
@app.route('/admin/blahxyz')
def admin_portal():
    if not session.get('admin_logged_in'):
        flash('Please log in as admin.')
        return redirect(url_for('home'))
    categories = Category.query.all()
    orders = AdminOrder.query.all()
    users = User.query.all()
    products = Product.query.all()  # Pass products for Manage Products modal
    total_sales = db.session.query(db.func.sum(AdminOrder.total_price)).filter(AdminOrder.status == 'delivered').scalar() or 0
    return render_template('admin_portal.html', categories=categories, orders=orders, users=users, products=products, total_sales=total_sales)

# Add category
@app.route('/admin/add-category', methods=['POST'])
def add_category():
    if not session.get('admin_logged_in'):
        flash('Admin access required.')
        return redirect(url_for('home'))
    name = request.form['name']
    if Category.query.filter_by(name=name).first():
        flash('Category already exists.')
        return redirect(url_for('admin_portal'))
    new_category = Category(name=name)
    db.session.add(new_category)
    db.session.commit()
    flash('Category added successfully.')
    return redirect(url_for('admin_portal'))

# Delete category
@app.route('/admin/delete-category/<int:category_id>', methods=['POST'])
def delete_category(category_id):
    if not session.get('admin_logged_in'):
        flash('Admin access required.')
        return redirect(url_for('home'))
    category = Category.query.get_or_404(category_id)
    if Product.query.filter_by(category_id=category_id).first():
        flash('Cannot delete category with associated products.')
        return redirect(url_for('admin_portal'))
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted successfully.')
    return redirect(url_for('admin_portal'))

# Add product
@app.route('/admin/add-product', methods=['POST'])
def admin_add_product():
    if not session.get('admin_logged_in'):
        flash('Admin access required.')
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
                    flash('Invalid file extension.')
                    return redirect(url_for('admin_portal'))
    category_id = request.form['category']
    name = request.form['name']
    quantity = int(request.form['quantity'])
    description = request.form['description']
    price = float(request.form['unit_price'])
    new_product = Product(name=name, category_id=category_id, quantity=quantity, description=description, price=price)
    new_product.images = ','.join(uploaded_file_paths)
    db.session.add(new_product)
    db.session.commit()
    flash('Product added successfully.')
    return redirect(url_for('admin_portal'))

# Edit product
@app.route('/admin/edit-product/<int:product_id>', methods=['POST'])
def edit_product(product_id):
    if not session.get('admin_logged_in'):
        flash('Admin access required.')
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    try:
        # Update product fields
        product.name = request.form['name']
        product.category_id = request.form['category']
        product.quantity = int(request.form['quantity'])
        product.description = request.form['description']
        product.price = float(request.form['unit_price'])

        # Handle image updates
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
            if uploaded_file_paths:  # Only update images if new ones are uploaded
                product.images = ','.join(uploaded_file_paths)

        db.session.commit()
        flash('Product updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error updating product: {str(e)}")
        flash(f'Error updating product: {str(e)}', 'danger')
    
    return redirect(url_for('admin_portal'))

# Delete product
@app.route('/admin/delete-product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if not session.get('admin_logged_in'):
        flash('Admin access required.')
        return redirect(url_for('home'))
    
    product = Product.query.get_or_404(product_id)
    try:
        # Check if product is in any orders or carts
        if product.user_orders or product.carts:
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

# Update order status
@app.route('/admin/update-order-status/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    if not session.get('admin_logged_in'):
        flash('Admin access required.')
        return redirect(url_for('home'))
    
    try:
        order = AdminOrder.query.get_or_404(order_id)
        print(f"AdminOrder found: ID={order.id}, Status={order.status}, UserID={order.user_id}, "
              f"ProductID={order.product_id}, OrderedAt={order.ordered_at}")

        status = request.form.get('status')
        print(f"Received status: {status}")

        if status not in ['pending', 'delivered', 'canceled']:
            flash(f'Invalid status: {status}', 'danger')
            return redirect(url_for('admin_portal'))

        time_window = timedelta(seconds=1)
        user_order = UserOrder.query.filter(
            UserOrder.user_id == order.user_id,
            UserOrder.product_id == order.product_id,
            UserOrder.ordered_at.between(order.ordered_at - time_window, order.ordered_at + time_window)
        ).first()

        if user_order:
            print(f"UserOrder found: ID={user_order.id}, Status={user_order.status}, OrderedAt={user_order.ordered_at}")
        else:
            print(f"No matching UserOrder found for AdminOrder ID={order.id}. "
                  f"Query criteria: user_id={order.user_id}, product_id={order.product_id}, "
                  f"ordered_at between {order.ordered_at - time_window} and {order.ordered_at + time_window}")

        order.status = status
        if user_order:
            user_order.status = status
            print(f"Updating UserOrder ID={user_order.id} to status={status}")
        else:
            flash('No matching UserOrder found. Only AdminOrder status updated.', 'warning')

        db.session.commit()
        print(f"Database commit successful. AdminOrder ID={order.id} status={order.status}" + 
              (f", UserOrder ID={user_order.id} status={user_order.status}" if user_order else ""))

        flash('Order status updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error updating order status: {str(e)}")
        flash(f'Error updating order status: {str(e)}', 'danger')
    
    return redirect(url_for('admin_portal'))

# Cancel order (customer)
@app.route('/cancel-order/<int:order_id>', methods=['POST'])
@login_required
def cancel_order(order_id):
    user_order = UserOrder.query.filter_by(id=order_id, user_id=current_user.id).first()
    if not user_order:
        flash('Order not found.')
        return redirect(url_for('profile'))
    if user_order.status != 'pending':
        flash('Cannot cancel non-pending order.')
        return redirect(url_for('profile'))
    admin_order = AdminOrder.query.filter_by(user_id=current_user.id, product_id=user_order.product_id, ordered_at=user_order.ordered_at).first()
    user_order.status = 'canceled'
    if admin_order:
        admin_order.status = 'canceled'
    product = Product.query.get(user_order.product_id)
    product.quantity += user_order.quantity
    db.session.commit()
    flash('Order canceled successfully.')
    return redirect(url_for('profile'))

# Delete user
@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('admin_logged_in'):
        flash('Admin access required.')
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.')
    return redirect(url_for('admin_portal'))

# Product details
@app.route('/product/<int:product_id>')
def product_details(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_details.html', product=product)

# Add to cart
@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    try:
        quantity = int(request.form.get('quantity', 0))
        if quantity <= 0:
            flash('Quantity must be a positive number.')
            return redirect(url_for('home'))

        product = Product.query.get(product_id)
        if not product:
            flash('Product not found.')
            return redirect(url_for('home'))

        if quantity > product.quantity:
            flash(f'Only {product.quantity} units available for {product.name}.')
            return redirect(url_for('home'))

        cart_item = UserCart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if cart_item:
            cart_item.quantity += quantity
        else:
            new_cart_item = UserCart(user_id=current_user.id, product_id=product_id, quantity=quantity)
            db.session.add(new_cart_item)

        db.session.commit()
        flash('Product added to cart successfully.', 'success')
        print(f"Add to cart: Product {product_id}, quantity {quantity} for user {current_user.id}")
    except ValueError:
        flash('Invalid quantity provided.')
    except Exception as e:
        flash(f'An error occurred: {str(e)}')
    return redirect(url_for('home'))

# Update cart quantity
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
        print(f"Update cart quantity: Product {product_id}, new_quantity {new_quantity} for user {current_user.id}")
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Cart item not found.'})

# Checkout
@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    transaction_code = request.form['transaction-code']
    print(f"Checkout endpoint: transaction_code='{transaction_code}'")
    if re.match(r'^[Ss]\w{9}$', transaction_code):
        cart_items = UserCart.query.filter_by(user_id=current_user.id).all()
        try:
            for cart_item in cart_items:
                product = Product.query.get(cart_item.product_id)
                if product:
                    if cart_item.quantity <= product.quantity:
                        product.quantity -= cart_item.quantity
                        ordered_at = datetime.utcnow()
                        new_order = UserOrder(
                            user_id=current_user.id,
                            product_id=product.id,
                            quantity=cart_item.quantity,
                            total_price=cart_item.quantity * product.price,
                            pickup_location=current_user.pickup_location,
                            ordered_at=ordered_at
                        )
                        db.session.add(new_order)
                        all_order = AdminOrder(
                            user_id=current_user.id,
                            product_id=product.id,
                            quantity=cart_item.quantity,
                            total_price=cart_item.quantity * product.price,
                            pickup_location=current_user.pickup_location,
                            ordered_at=ordered_at
                        )
                        db.session.add(all_order)
                        db.session.delete(cart_item)
                    else:
                        flash(f"Not enough quantity available for {product.name}.", 'danger')
                        return redirect(url_for('profile'))
            db.session.commit()
            print(f"Checkout successful: {len(cart_items)} orders created.")
            flash('Order placed successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            print(f"Error during checkout: {str(e)}")
            flash(f'Checkout failed: {str(e)}', 'danger')
        return redirect(url_for('profile'))
    flash('Invalid transaction code.', 'error')
    return redirect(url_for('profile'))

# Remove from cart
@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    cart_item = UserCart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
        flash('Product removed from cart.')
        print(f"Remove from cart: Product {product_id} for user {current_user.id}")
    else:
        flash('Product not found in cart.')
    return redirect(url_for('profile'))

# Search
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    if query:
        products = Product.query.filter(Product.name.ilike(f"%{query}%")).all()
        return render_template('home.html', categories=Category.query.all(), products=products, cart_items=[], orders=[], cart_total=0)
    flash('Please enter a search query.')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)