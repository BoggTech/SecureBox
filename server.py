import os, time, json
import modules.globals as globals
from pathlib import Path
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from modules.globals import decrypt, build_response

"""
KEY SERVER
This server serves a few purposes
- Keep track of and distribute public keys of users on the network
- Ditto, for users in the group
- Receive public-key encrypted AES keys for files on the box and distribute them appropriately.
AES encryption is done by the users, and is never stored on the server.
"""

# server's public key should be generated beforehand and put on machines

users = {} # user: public key
group = {} # ditto
keys = {} # user: {file: key}
always_group = [] # list of usernames that should always be in the group

if os.path.exists("data\\users"):
    users = json.loads(open("data\\users", "r").read())
    for new_user in users:
        users[new_user] = serialization.load_pem_public_key(users[new_user].encode("utf-8"))
if os.path.exists("data\\groups"):
    group = json.loads(open("data\\groups", "r").read())
    for new_group in group:
        group[new_group] = serialization.load_pem_public_key(group[new_group].encode("utf-8"))
if os.path.exists("data\\keys"):
    keys = json.loads(open("data\\keys", "r").read())

# pre-auth: public keys in this directory are automatically added to the group
if os.path.exists("preauth") and os.path.isdir("preauth"):
    for file in os.listdir("preauth"):
        if not file.endswith(".pem"):
            continue
        keyfile = open("preauth\\" + file, mode="rb").read()
        public_key = serialization.load_pem_public_key(keyfile)
        username = Path(file).stem
        users[username] = public_key
        group[username] = public_key
        always_group.append(username)

def save_data():
    new_users = {}
    new_groups = {}
    for user in users:
        new_users[user] = globals.serialize_public_key(users[user]).decode("utf-8")
    for new_group in group:
        new_groups[new_group] = globals.serialize_public_key(group[new_group]).decode("utf-8")

    if os.path.exists("data\\users"):
        os.remove("data\\users")
    with open("data\\users", "w") as file:
        file.write(json.dumps(new_users))
    if os.path.exists("data\\groups"):
        os.remove("data\\groups")
    with open("data\\groups", "w") as file:
        file.write(json.dumps(new_groups))
    if os.path.exists("data\\keys"):
        os.remove("data\\keys")
    with open("data\\keys", "w") as file:
        file.write(json.dumps(keys))

pem_location = "auth\\-server-private.pem"
private_key = None
while not private_key:
    password = input("Enter server PEM password: ").encode('utf-8')
    try:
        with open(pem_location, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
            )
    except Exception as e:
        print(e)
        pass


try:
    app = Flask(__name__)
except Exception as e:
    save_data()

@app.route("/getusers", methods=["GET"])
def get_users():
    """ Returns a dict of users and their public keys. Can be verified with server's public key
    field "json" will be signed with field "signature". signature is b64 encoded."""
    # make a new dict with serialized keys
    new_users = {}
    for user in users:
        new_users[user] = globals.serialize_public_key(users[user]).decode("utf-8")

    return build_response(new_users, private_key)

@app.route("/getgroup", methods=["GET"])
def get_group():
    """ Returns a dict of group users and their public keys. Can be verified with server's public key
    field "json" will be signed with field "signature". signature is b64 encoded.
    """
    # make a new dict with serialized keys
    new_group = {}
    for user in group:
        new_group[user] = globals.serialize_public_key(group[user]).decode("utf-8")

    return build_response(new_group, private_key)

@app.route("/isuser/<name>", methods=["GET"])
def is_user(name):
    """Returns 200 with this users name and public key if they exist, 404 otherwise"""
    if name in users:
        key = globals.serialize_public_key(users[name]).decode("utf-8")
        return jsonify({name: key}), 200
    else:
        return jsonify({'message': 'User does not exist.'}), 404

@app.route("/isgroup/<name>", methods=["GET"])
def is_group(name):
    """Returns 200 with this users name and public key if they're in the group, 404 otherwise"""
    if name in group:
        key = globals.serialize_public_key(users[name]).decode("utf-8")
        return jsonify({name: key}), 200
    else:
        return jsonify({'message': 'User is not in group.'}), 404

@app.route("/adduser", methods=['POST'])
def register_me():
    """register a users public key with the server"""
    req = json.loads(request.json)
    username = req['username']
    serialized_key = req['key']

    if username in users:
        # already registered... shoo!
        return jsonify({'message': 'User already exists'}), 400

    # load the public key from this serialized data, then store it
    public_key = serialization.load_pem_public_key(serialized_key.encode("utf-8"))
    users[username] = public_key

    save_data()
    return jsonify({'message': 'User registered'}), 201

@app.route("/addgroup", methods=['POST'])
def add_to_group():
    """add an existing user to the group. user must verify with RSA and also be in the group.
    {"username", "username_to_add"}"""
    req = json.loads(request.json)
    info = json.loads(req['json'])
    username = info["username"]
    to_add = info["username_to_add"]

    if username not in group:
        return jsonify({'message': 'You are not in the group'}), 403
    if not to_add in users:
        return jsonify({'message': 'Requested user does not exist'}), 400
    if to_add in group:
        return jsonify({'message': 'Request user already in group'}), 400

    # verify this is really from our group user
    if globals.verify_response(req, group[username]) is None:
        return jsonify({'message': 'Failed to verify user'}), 400

    # add to group if they're legit
    group[to_add] = users[to_add]
    save_data()
    return jsonify({'message': 'Success!'}), 200

@app.route("/removegroup", methods=['POST'])
def remove_from_group():
    """remove an existing user from the group. user must verify with RSA and also be in the group.
    {"username", "username_to_remove"}. users can remove themselves... but, don't."""
    req = json.loads(request.json)
    info = json.loads(req['json'])
    username = info["username"]
    to_remove = info["username_to_remove"]

    if username not in group:
        return jsonify({'message': 'You are not in the group'}), 403
    if not to_remove in users:
        return jsonify({'message': 'Requested user does not exist'}), 400
    if not to_remove in group:
        return jsonify({'message': 'Request user not in group'}), 400
    if to_remove in always_group:
        return jsonify({'message': 'Can\'t remove user from group'}), 403

    # verify this is really from our group user
    if globals.verify_response(req, group[username]) is None:
        return jsonify({'message': 'Failed to verify user'}), 400

    # remove from the group and bin their keys
    if to_remove in group:
        group.pop(to_remove)
    if to_remove in keys:
        keys.pop(to_remove)
    save_data()
    return jsonify({'message': 'Success!'}), 200

@app.route("/getallkeys", methods=['POST'])
def get_all_keys():
    """Returns all of a users keys for all encrypted files. The keys will be encrypted with their public key."""
    req = json.loads(request.json)
    info = json.loads(req['json'])
    username = info["username"]
    username_to_fetch = info["username_to_fetch"]

    if username not in group:
        return jsonify({'message': 'You are not in the group'}), 403
    if username_to_fetch not in group:
        return jsonify({'message': 'Requested user is not in the group'}), 400

    # verify this is really from our group user
    if globals.verify_response(req, group[username]) is None:
        return jsonify({'message': 'Failed to verify user'}), 400

    return build_response(keys[username_to_fetch], private_key) \
        if username_to_fetch in keys else build_response({}, private_key)

@app.route("/insertkeys", methods=['POST'])
def insert_keys():
    """insert new keys for a collection of files/users. should supply username and then a dict
    of {username: {filename: key}}. if any users aren't in the group, they'll be automatically added here.
    """
    req = json.loads(request.json)
    info = json.loads(req['json'])
    username = info["username"]
    new_keys = info["keys"]

    if username not in group:
        return jsonify({'message': 'You are not in the group'}), 403
    # verify this is really from our group user
    if globals.verify_response(req, group[username]) is None:
        return jsonify({'message': 'Failed to verify user'}), 400

    for user in new_keys:
        if user not in group:
            if user not in users:
                continue                  # garbage user, don't add them
            else:
                group[user] = users[user] # not in group, add them.
        if user not in keys:
            keys[user] = {}
        for filename in new_keys[user]:
            keys[user][filename] = new_keys[user][filename]

    save_data()
    return jsonify({'message': 'Keys added'}), 200

@app.route("/getkey", methods=['POST'])
def get_file_key():
    """gets a key for a specific file for a specific user
    {username:, filename:}"""
    req = json.loads(request.json)
    info = json.loads(req['json'])
    username = info["username"]
    filename = info["filename"]

    if username not in group:
        return jsonify({'message': 'You are not in the group'}), 403
    if globals.verify_response(req, group[username]) is None:
        return jsonify({'message': 'Failed to verify user'}), 400

    return build_response({"key": keys[username][filename]}, private_key) \
        if username in keys and filename in keys[username] else build_response({}, private_key)





