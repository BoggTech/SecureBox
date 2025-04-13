from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

"""
PREAUTH

This script creates two PEM files:
- One private key, in 'auth'. This is used for logging in locally.
- One public key, in 'preauth'. PEM files in this folder will be loaded as a public key on the server and 
  automatically added to the group.
"""

username = input("Enter username for preauth user: ")

pem_location = "..\\auth\\" + username + ".pem"
# generate a new private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

password = input("Enter pre-auth PEM password: ")

# serialize and store to .pem
serialized_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
)

with open(pem_location, "wb") as f:
    f.write(serialized_key)

pem_location = "..\\preauth\\" + username + ".pem"
public_key = private_key.public_key()
serialized_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

with open(pem_location, "wb") as f:
    f.write(serialized_public_key)