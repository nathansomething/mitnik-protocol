import socket
import threading
import select
import time
import sys
import argparse
import json
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from util import *
from module import *

parser = argparse.ArgumentParser()
parser.add_argument("-sip", help="server ip", default="localhost")
parser.add_argument("-sp", help="server port", type=int, default=9090)
args = parser.parse_args()
serverIp = args.sip
serverPort = args.sp

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(0)
keepAlive = True

SERVER_PUBLIC_KEY = "public_key.der"

###############################################################################
## Authentication Handler
###############################################################################
class AuthenticationHandler():
    def __init__(self, username, password, key):
        self.username = username
        self.password = password
        self.key = key
        
    def run(self):
        print "i am here"
        nonce = genNonce()
        firstMessage = self.generateFirstMessage(self.username, self.password, nonce, self.key.public_key())

        print firstMessage

        sock.send(firstMessage)
        response = sock.recv(1024)
        decodedResponse = json.loads(response)

        if decodedResponse['type'] == 'authentication':
            content = decodedResponse['content']

            decryptedMessage2 = asym_decrypt(content, self.key)
            if decryptedMessage2['nonce1'] == nonce:
                nonce2 = decryptedMessage2['nonce2']
                signedNonce2 = sign(nonce2, self.key)

                thirdMessage = self.generateThirdAuthenticationMessage(signedNonce2)
                sock.send(thirdMessage)
                response = sock.recv(1024)
                decodedResponse = json.loads(response)

                content = decodedResponse['content']
                verify(int(nonce2)+1, content, SERVER_PUBLIC_KEY)

            else:
                raise Exception("Wrong nonce")

        elif decodedResponse['type'] == 'error':
            raise Exception("Wrong nonce")

    def generateFirstMessage(self, username, password, nonce, pubKey):

        firstMessage = {}
        firstMessage["type"] = "authentication"
        firstMessage["order"] = 1
        
        content = {}

        content["user"] = username
        content["password"] = password
        content["nonce"] = nonce
        print "right here"
        content["publicKey"] = pubKey.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        contentDump = json.dumps(content)
        print contentDump
        print len(contentDump)
        encodedContent = asym_encrypt_from_file(json.dumps(content), SERVER_PUBLIC_KEY)

        firstMessage["content"] = base64.b64encode(encodedContent)

        return json.dumps(firstMessage)

    def generateThirdAuthenticationMessage(self, signedNonce):
        thirdMessage = {}
        thirdMessage["type"] = "authentication"
        thirdMessage["order"] = 3

        content = {}
        content["sender"] = self.username
        content["signature"] = signedNonce

        thirdMessage["content"] = content

        return json.dumps(thirdMessage)


###############################################################################
## Main functions
###############################################################################
def authenticate():
    username = raw_input(">> Username: ")
    password = raw_input(">> Password: ")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )

    authenticationHandler = AuthenticationHandler(username, password, private_key)
    try:
        authenticationHandler.run()
    except Exception as err:
        print "authentication fail"
        print err

def main():
    login = False
    while True:
        if not login:
            authenticate()



###############################################################################
## Run program
###############################################################################
            
if __name__ == "__main__":
    main()

