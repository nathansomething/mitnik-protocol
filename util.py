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
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

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
def verify(text, public_key):
    signature = read_file('signature')
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
