from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Import models here to avoid circular imports
from application.models import User 