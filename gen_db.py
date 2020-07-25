from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData

# Create database and table
engine = create_engine('sqlite:///database.sql', echo=True)

meta = MetaData()

users = Table(
    'users', meta,
    Column('id', Integer, primary_key=True),
    Column('username', String, unique=True),
    Column('password', String),
)

meta.create_all(engine)

# Generate test data

from app.user import User

User.gen_test_data(username='sharefun', password='123456')

print(User.query.filter_by(username='sharefun').first())
