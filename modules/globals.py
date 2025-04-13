import base64
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json
import tkinter as tk
import tkinter.messagebox
import requests
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

server_addr = "http://127.0.0.1:5000"
COOLDOWN = 2000

DEFAULT_PADDING = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def decrypt(message, private_key):
    """decrypt messages encrypted with our public key"""
    return private_key.decrypt(message, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

def encrypt(message, public_key):
    """encrypt messages encrypted with someone else's public key"""
    return public_key.encrypt(message, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

def post_server(path, request):
    json_req = json.dumps(request)
    return requests.post(server_addr + path, json=json_req)

def get_server(path):
    return requests.get(server_addr + path)

def sign_message(message, private_key):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_message(message, signature, public_key):
    return public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_response(response, public_key):
    """given a requests response, verify it and return the value.
    our server should return responses in the form {"json": "", "signature": "" where signature is b64 encoded.}"""
    json_resp = response["json"]                                    # get response
    json_bytes = json_resp.encode("utf-8")                          # encode to bytes for verification
    hashed = sha256_encrypt(json_bytes)                             # get hashed data
    signature = base64.b64decode(response["signature"].encode("utf-8")) # restore signature to bytes

    try:
        verify_message(hashed, signature, public_key)
    except Exception as e:
        print(e)
        return None

    # return the actual json
    return json.loads(json_resp)

def build_response(response, private_key):
    """given a desired response and a private key, build a response for the server to send out
    with a verification key.
    """
    response_json = json.dumps(response)                                  # convert to string
    response_bytes = response_json.encode("utf-8")                        # convert to bytes
    hashed = sha256_encrypt(response_bytes)                               # get hashed data
    signature = sign_message(hashed, private_key)                         # sign the json
    signature = base64.b64encode(signature).decode("utf-8")
    return {"json": response_json, "signature": signature}

def sha256_encrypt(plaintext_bytes):
    return hashlib.sha256(plaintext_bytes).hexdigest().encode("utf-8")

def aes_encrypt_file(input_bytes):
    """method to encrypt a field of bytes. returns a tuple of the key and encrypted file."""
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(input_bytes) + encryptor.finalize()
    return key + iv, ct

def aes_decrypt_file(full_key, ciphertext):
    """method to decrypt a file given a key and encrypted bytes."""
    key = full_key[:32]
    iv = full_key[32:48]
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()