import time
from datetime import datetime
from datetime import timedelta

import jwt
from flask import current_app

from flaskpanel import db, login_manager
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    date_registered = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    v_code = db.relationship('ResetPassword', backref='user', lazy='dynamic')

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.date_registered}')"

    @staticmethod
    def is_exist(username=None, email=None):
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return True
        return False

    @staticmethod
    def verify_token(token):
        try:
            user_dict = jwt.decode(token, current_app.config['SECRET_KEY'], options={}, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return None
        try:
            user_id = user_dict['user_id']
        except:
            return None
        return User.query.get(user_id)




    def generate_token(self, seconds=300):
        user_dict = {"user_id": self.id, "exp": datetime.utcnow() + timedelta(seconds=seconds)}
        user_token = jwt.encode(payload=user_dict, key=current_app.config['SECRET_KEY'])
        return user_token.decode('utf-8')


class ResetPassword(db.Model):
    __tablename__ = 'resetpassword'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    verify_code = db.Column(db.String(10), nullable=True, default=None)
    generate_time = db.Column(db.Integer, nullable=True, default=int(time.time()))
