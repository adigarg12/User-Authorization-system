from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from config import Config
from models import User
from models import db
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

@app.route('/')
def home():
    return "Home Page"

# User Registration
@app.route('/register', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email is already in use. Please choose another one.', 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('There was an error creating the user. Please try again.', 'danger')
            print(f"Error: {e}")  # Optional: Log the exception for debugging
            return render_template('register.html')

    return render_template('register.html')

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html')

# Dashboard (protected route)
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return f"Welcome {session['username']}!"
    else:
        flash('You need to login first', 'danger')
        return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have logged out!', 'success')
    return redirect(url_for('login'))

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates the DB if it doesn't exist
    app.run(debug=True)
