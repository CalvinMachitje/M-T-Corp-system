from flask import Flask, render_template, request, redirect, url_for, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'X7k9PqRwL2mN4vJxZ5yH8uTaC3eFoGb'  # String, not bytes
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin.login'  # Blueprint 'admin' login route

# Admin model for database
class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Create database tables
with app.app_context():
    db.create_all()

# Blueprint for admin routes
admin_bp = Blueprint('admin', __name__, template_folder='templates/admin')

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# Admin login route
@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            login_user(admin)
            return redirect(url_for('admin.dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

# Admin logout route
@admin_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('admin.login'))

# Admin dashboard and other pages routes
@admin_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('admin/dashboard.html', title='Dashboard')

@admin_bp.route('/properties')
@login_required
def properties():
    return render_template('admin/properties.html', title='Properties Management')

@admin_bp.route('/music')
@login_required
def music():
    return render_template('admin/music.html', title='Music Management')

@admin_bp.route('/codeacademy')
@login_required
def codeacademy():
    return render_template('admin/codeacademy.html', title='Code Academy Management')

@admin_bp.route('/eats')
@login_required
def eats():
    return render_template('admin/eats.html', title='Eats Management')

@admin_bp.route('/communityhub')
@login_required
def communityhub():
    return render_template('admin/communityhub.html', title='Community Hub Management')

@admin_bp.route('/techsolutions')
@login_required
def techsolutions():
    return render_template('admin/techsolutions.html', title='Tech Solutions Management')

@admin_bp.route('/security')
@login_required
def security():
    return render_template('admin/security.html', title='Security Management')

@admin_bp.route('/transport')
@login_required
def transport():
    return render_template('admin/transport.html', title='Transport Management')

@admin_bp.route('/livestock')
@login_required
def livestock():
    return render_template('admin/livestock.html', title='Livestock Management')

@admin_bp.route('/financials')
@login_required
def financials():
    return render_template('admin/financials.html', title='Financials Management')

@admin_bp.route('/crypto')
@login_required
def crypto():
    return render_template('admin/crypto.html', title='Crypto Management')

@admin_bp.route('/reports')
@login_required
def reports():
    return render_template('admin/reports.html', title='Reports Management')

# Register blueprint with URL prefix /admin
app.register_blueprint(admin_bp, url_prefix='/admin')

# Initialize admin user (run once)
with app.app_context():
    if not Admin.query.filter_by(username='sello').first():
        admin = Admin(username='sello', email='sello@mntcorp.com', full_name='Sello Calvin Machitje')
        admin.password = 'admin123'  # This automatically hashes the password
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)