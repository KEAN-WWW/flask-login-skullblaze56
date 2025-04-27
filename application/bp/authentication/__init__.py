from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, login_required, current_user, logout_user
from application.bp.authentication.forms import RegisterForm
from application.models import User

authentication = Blueprint('authentication', __name__, template_folder='templates')

@authentication.route('/registration', methods=['POST', 'GET'])
def registration():
    pass


@authentication.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('authentication.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('User Not Found', 'error')
            return redirect(url_for('authentication.login'))
            
        if not user.check_password(password):
            flash('Password Incorrect', 'error')
            return redirect(url_for('authentication.login'))
            
        # Login successful
        login_user(user)
        return redirect(url_for('authentication.dashboard'))

    return render_template('auth/login.html')


@authentication.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('homepage.homepage'))


@authentication.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')
