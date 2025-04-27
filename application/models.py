from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from application.database import db

class User(db.Model, UserMixin):
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Changed from password_hash to password

    @classmethod
    def create(cls, email, password):
        """Create a new user instance"""
        user = cls()
        user.email = email
        user.password = generate_password_hash(password)  # Store hash in password field
        return user

    def set_password(self, password):
        if not password:
            raise ValueError("Password cannot be empty")
        self.password = generate_password_hash(password)  # Store in password field

    def check_password(self, password):
        if not self.password:
            return False
        return check_password_hash(self.password, password) 