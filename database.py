import os

from peewee import *

dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, '../database.db')

db = SqliteDatabase(filename)


class BaseModel(Model):
    class Meta:
        database = db


#
# Tables
#


class Domain(BaseModel):
    domain = CharField(unique=True)
    password = CharField()

    date = DateTimeField(null=True)


class User(BaseModel):
    domain = ForeignKeyField(Domain, backref="users")
    password = CharField()

    # Extensions
    alias = CharField(unique=True)
    date = DateTimeField(null=True)


class Type(BaseModel):
    address_type = IntegerField()
    user = ForeignKeyField(User, backref="types")
    address = CharField(null=True)


tables = [Domain, User, Type]

if __name__ == "__main__":
    db.create_tables(tables)
