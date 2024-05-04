from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Account(db.Model):
    account_id = db.Column(db.String(80), primary_key=True)
    password = db.Column(db.String(128), nullable=False)
    join_date = db.Column(db.DateTime, nullable=False)
    role = db.Column(db.String(50), nullable=False)  # Include roles like 'admin' or 'customer'
