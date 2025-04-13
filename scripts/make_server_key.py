from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

"""
SERVER KEY
This created a public and private key for the server.

The public key should be provided to all users at the start. The private key will only be available 
on the server itself. The private key will also be password-protected.

Dashes used in the name to distinguish it from a normal user.
"""

pem_location = "..\\auth\\-server-private.pem"
# generate a new private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

password = input("Enter server PEM password: ")

# serialize and store to .pem
serialized_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
)

with open(pem_location, "wb") as f:
    f.write(serialized_key)

pem_location = "..\\auth\\-server-public.pem"
public_key = private_key.public_key()
serialized_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

with open(pem_location, "wb") as f:
    f.write(serialized_public_key)