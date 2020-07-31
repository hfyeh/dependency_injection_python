from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../database.sql'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=True, nullable=False)

    @staticmethod
    def gen_test_data(username: str, password: str):
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()

    def __repr__(self):
        return f'<id: {self.id}, username: {self.username}, password: {self.password}>'

    def get_password_from_db(self, username: str) -> str:
        password_from_db = User.query.filter_by(username=username).first().password
        return password_from_db
