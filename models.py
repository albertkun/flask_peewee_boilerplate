# Import from peewee
from peewee import *
from flask import session
from playhouse.postgres_ext import PostgresqlExtDatabase

# load the config file
from config import Config
from flask_peewee.auth import Auth
from flask_peewee.db import Database

# used for passwords
# from flask_bcrypt import generate_password_hash, check_password_hash


# Connect to the PostgresqlDatabase
db = PostgresqlDatabase(database=Config.DATABASE, user=Config.USERNAME, password=Config.SECRET_KEY,
host=Config.HOST, port=Config.PORT)

db.connect()



class Default(Model):
    uid = IntegerField(primary_key=True)

    class Meta:
        database = db
        db_table = 'default'