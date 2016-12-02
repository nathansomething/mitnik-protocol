from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

import random

# Helper function for writing to a file
def write_file(text, path):
    with open(path, 'w') as output_file:
        output_file.write(text)

# Helper function for reading from a file
def read_file(path):
    with open(path, 'r') as input_file:
        return input_file.read()

# Helper function for using Asymetric Encryption
def asym_encrypt(text, public_key):
    return public_key.encrypt(
        text,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

def asym_encrypt_from_file(text, filename):
     with open(filename, "rb") as key_file:
        public_key = serialization.load_der_public_key(
            key_file.read(),
            backend=default_backend()
        )
        return asym_encrypt(text, public_key)

    
# Helper function for using Asymetric Decryption
def asym_decrypt(text, private_key):
    return private_key.decrypt(
        text,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def asym_decrypt_from_file(text, key_file):
    key = serialization.load_der_public_key(key_file, backend=default_backend())
    asym_encrypt(key)

# Generates a new nonce
def genNonce():
    return random.random() * 100000;

# Signs the message, which keeps a record which can later be used to varify
# the identity of the sender
def sign(text, private_key):
    signer = private_key.signer(
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signer.update(text)
    signature = signer.finalize()
    return signature

# Verify that the message was signed by the correct private key.
# This ensures that the sender is who they say thay are
def verify(text, signature, public_key):
    verifier = public_key.verifier(
        signature,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    try:
        verifier.update(text)
        verifier.verify()
    except InvalidSignature:
        print("The signurate dosen't match the sender's key")
        sys.exit()
