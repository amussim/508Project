from flask import Flask, request, render_template, redirect, url_for, flash
import mysql.connector
from mysql.connector import Error
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from models import db, Account






app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yourdatabase.db'




# When creating a new user
password_hash = generate_password_hash('your_password')

# When checking a user's password
check_password_hash(password_hash, 'provided_password')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader callback
@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(user_id)

def get_db_connection():
    try:
        conn = mysql.connector.connect(
        host='cmsc508.com',
        user='24SP_mussima',  # replace with actual user ID
        password='V00912804',
        database='24SP_mussima_pr'  # replace with actual database name
        )
        return conn
    except Error as e:
        print(f"Error connecting to MySQL Platform: {e}")

@app.route('/')
def home():
    return render_template('home.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Account.query.filter_by(account_id=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('customer_dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/dlc')
def dlc():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # Set cursor to return dictionary results
    cursor.execute('SELECT dlc_id, price FROM DLC')
    dlcs = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('dlc.html', dlcs=dlcs)


@app.route('/products')
def products():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM Product')
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('products.html', products=products)

@app.route('/hardware')
def hardware():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT identification, brand FROM Hardware')
    hardware_items = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('hardware.html', hardware_items=hardware_items)

@app.route('/videogames')
def videogames():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT product_id, age_rating, genre FROM Videogame')
    videogames = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('videogames.html', videogames=videogames)


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return "Access Denied", 403
    return "Welcome to the Admin Dashboard"

@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    return "Welcome to the Customer Dashboard"

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

if __name__ == '__main__':
    db.init_app(app)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
