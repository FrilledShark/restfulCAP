import json
import os
from datetime import datetime, timedelta

import jwt
from flask import abort, jsonify
from peewee import IntegrityError, PeeweeException

from .database import Coin, Domain, User
from .passlib_context import pwd_context

dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, '../config.json')
with open(filename, 'r') as file:
    config = json.load(file)

jwt_secret = config["secret"]
dt_format = "%Y-%m-%d %H:%M:%S"
print("HE")


# Phrase Alias
def phrase_alias(alias):
    username, domain = alias.split("@")
    rqst_domain = f'opencap.{domain}'
    return rqst_domain, username


def array_lower(oldarray):
    new_array = []
    for instance in oldarray:
        new_array.append(instance.lower())
    return new_array


#
# CAP
# https://github.com/opencap/protocol/blob/master/CAP.md
#


# No Authorization (Public method)
def v1_get_address_with(alias, address_type):
    rqst_domain, username = array_lower(phrase_alias(alias))
    try:
        # cAsE iNSnSeTivE username and coin.
        user = User.select().join(Domain).where(
            User.username == username and Domain.domain == rqst_domain).get()
        address = ""
        for type_instance in user.types:
            if type_instance.address_type == address_type:
                address = type_instance.address
                break
        if address:
            extensions = dict(name=username)
            to_return = dict(
                address_type=address_type,
                address=address,
                extensions=extensions)
            return jsonify(to_return)
        else:
            abort(404)
    except (PeeweeException, User.DoesNotExist):
        abort(404)


#
# CAMP Tier 2 endpoint
# https://github.com/opencap/protocol/blob/master/CAMP.md
#


# No Authorization (Public method)
def v1_auth(request):
    rqst_domain = request.headers['Host'].lower()
    username = request.json['Username'].lower()
    password = request.json['password']
    try:
        user = User.select().join(Domain).where(
            User.username == username and Domain.domain == rqst_domain).get()
        if pwd_context.verify(password, user.password):
            encoded = jwt.encode(
                {
                    'u': username,
                    'd': datetime.now().strftime(dt_format)
                },
                key=jwt_secret)
            return jsonify(jwt=encoded.decode())
        else:  # Wrong password
            abort(401)
    except (PeeweeException, User.DoesNotExist):
        abort(404)


# Authorization: Bearer {jwt}
def v1_delete_user(request):
    rqst_domain = request.headers['Host'].lower()
    jwt_token = request.headers['Authorization'].replace("Bearer ", "")
    try:
        jwt_decoded = jwt.decode(jwt_token, key=jwt_secret)
        username = jwt_decoded["u"]
        dt_jwt = datetime.strptime(jwt_decoded["d"], dt_format)
        if dt_jwt > datetime.now() - timedelta(minutes=5):
            user = User.select().join(Domain).where(
                User.username == username
                and Domain.domain == rqst_domain).get()
            for coin in user.coins:
                coin.delete_instance()
            user.delete_instance()
            return jsonify(success=True)
        else:
            abort(401)
    except jwt.InvalidSignatureError:
        abort(401)


# Authorization: Bearer {jwt}
def v1_put_address(request):
    rqst_domain = request.headers['Host'].lower()
    jwt_token = request.headers['Authorization'].replace("Bearer ", "")
    req_coin = request.json["coin"]
    req_address = request.json["address"]
    try:
        jwt_decoded = jwt.decode(jwt_token, key=jwt_secret)
        username = jwt_decoded["u"]
        dt_jwt = datetime.strptime(jwt_decoded["d"], dt_format)
        if dt_jwt > datetime.now() - timedelta(minutes=5):
            user = User.select().join(Domain).where(
                User.username == username
                and Domain.domain == rqst_domain).get()
            coin_instance, created = Coin.get_or_create(
                user=user, coin=req_coin)
            coin_instance.address = req_address
            coin_instance.save()
            return jsonify(success=True)
        else:
            abort(401)
    except jwt.InvalidSignatureError:
        abort(404)


# Authorization: Bearer {jwt}
def v1_delete_address(request, ledger_id):
    rqst_domain = request.headers['Host'].lower()
    jwt_token = request.headers['Authorization'].replace("Bearer ", "")
    try:
        jwt_decoded = jwt.decode(jwt_token, key=jwt_secret)
        username = jwt_decoded["u"]
        dt_jwt = datetime.strptime(jwt_decoded["d"], dt_format)
        if dt_jwt > datetime.now() - timedelta(minutes=5):
            user = User.select().join(Domain).where(
                User.username == username
                and Domain.domain == rqst_domain).get()
            coin = Coin.select().where(Coin.user == user
                                       and Coin.ledger_id == ledger_id).get()
            coin.delete_instance()
            return jsonify(success=True)
        else:
            abort(401)
    except jwt.InvalidSignatureError:
        abort(401)


#
# Not CCAP, but domain control
#


# Authorization: Auth {Secret}
def private_user(request):
    domain_name = request.headers["Host"]
    secret = request.headers['Authorization'].replace("Auth ", "")
    username = request.json["username"]
    password = request.json["password"]
    try:
        domain = Domain.get(Domain.domain == domain_name)
        if pwd_context.verify(secret, domain.password):
            User.create(
                username=username,
                password=pwd_context.hash(password),
                domain=domain)
            return jsonify(success=True)
        else:
            abort(401)
    except IntegrityError:
        abort(409)
