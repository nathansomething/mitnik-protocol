from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

import json
import os
import base64


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
def asym_decrypt(cipher_text, private_key):
    return private_key.decrypt(
        cipher_text,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )


def asym_decrypt_from_file(text, filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_der_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        return asym_decrypt(text, private_key)


def get_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_der_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        return private_key


def get_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_der_public_key(
            key_file.read(),
            backend=default_backend()
        )
        return public_key


def load_public_key(key):
    public_key = serialization.load_pem_public_key(
        key,
        backend=default_backend()
    )
    return public_key


# Generates a new nonce
def gen_nonce():
    return base64.b64encode(os.urandom(64))


# Signs the message, which keeps a record which can later be used to verify
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
        return True

    except Exception:
        print 'wrong signature'
        return False


def sym_encrypt(text, key, iv):
    block_size = len(iv) * 8
    padded_text = pad(text, block_size)
    cipher = Cipher(algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_text) + encryptor.finalize()
    return ct

def sym_decrypt(text, key, iv):
    block_size = len(iv) * 8
    cipher = Cipher(algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    dt = decryptor.update(text) + decryptor.finalize()
    return unpad(dt, block_size)


def pad(text, block_size):
    padder = padding.PKCS7(block_size).padder()
    padded_data = padder.update(text) + padder.finalize()
    return padded_data

def unpad(text, block_size):
    unpadder = padding.PKCS7(block_size).unpadder()
    data = unpadder.update(text) + unpadder.finalize()
    return data

def hash256(text):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(text)
    return str(digest.finalize())

def construct_msg(msg_type, order, content):
    return {'type': msg_type, 'order': order, 'content': content}
