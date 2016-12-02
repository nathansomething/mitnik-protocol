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

parser = argparse.ArgumentParser()
parser.add_argument("-sip", help="server ip", default="localhost")
parser.add_argument("-sp", help="server port", type=int, default=9090)
args = parser.parse_args()
serverIp = args.sip
serverPort = args.sp

# This port is used to listen to the server
serverSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSock.setblocking(0)

# This port is used to listen to peer
peerSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
peerSock.setblocking(0)
peerSockNumber = peerSock.getsockname()[1]

keepAlive = True

SERVER_PUBLIC_KEY = "server_public_key.der"

###############################################################################
## Listener
###############################################################################
class ServerListener(threading.Thread):
    def __init__(self, threadId, name, sock):
        threading.Thread.__init__(self)
        self.threadId = threadId
        self.name = name
        self.sock = sock

    def run(self):
        global keepAlive
        while keepAlive:
            time.sleep(1)
            try:
                response = serverSock.recv(1024)
                decodedResponse = json.loads(response)
                msgToPrint = "<From {}:{}>: {}".format(decodedResponse['ip'], decodedResponse['port'], decodedResponse['content'])
                print msgToPrint
                sys.stdout.write("> ")
                sys.stdout.flush()
            except ValueError:
                # server sends somthing that cannot be decoded:
                print "invalid message from server: ", response
            except:
                # server doesn't send anything so ignore
                pass

class Listener(threading.Thread):
    def __init__(self, threadId, name, sock):
        pass
    def run(self):
        pass

###############################################################################
## Authentication Handler
###############################################################################
class AuthenticationHandler():
    def __init__(self, username, password, key):
        self.username = username
        self.password = password
        self.key = key
        
    def run(self):
        nonce = genNonce()
        firstMessage = self.generateFirstMessage(self.username, self.password, nonce, self.key.public_key())

        print firstMessage

        serverSock.send(firstMessage)
        response = serverSock.recv(1024)
        decodedResponse = json.loads(response)

        if decodedResponse['type'] == 'authentication':
            content = decodedResponse['content']

            decryptedMessage2 = asym_decrypt(content, self.key)
            if decryptedMessage2['nonce1'] == nonce:
                nonce2 = decryptedMessage2['nonce2']
                signedNonce2 = sign(nonce2, self.key)

                thirdMessage = self.generateThirdAuthenticationMessage(signedNonce2)
                serverSock.send(thirdMessage)
                response = serverSock.recv(1024)
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

class PeerConnectionHandler():
    def __init__(self, client, peer):
        # Username of the person we want to connect to
        self.peer = peer
        self.client = client

    def run(self):
        firstMessage = self.generateFirstMessage()
        print firstMessage

    def generateFirstMessage(self):
        firstMessage = {}
        firstMessage['type'] = 'key establishment'
        firstMessage['order'] = 1
        content = {}

        encodedUsername = asym_encrypt_from_file(self.peer, SERVER_PUBLIC_KEY)
        signedUsername = sign(encodedUsername, self.client.key)

        content['message'] = base64.b64encode(encodedUsername)
        content['signature'] = base64.b64encode(signedUsername)

        firstMessage['content'] = content

        return json.dumps(firstMessage)

    def generateThirdMessage(self, nonce):
        thirdMessage = {}
        thirdMessage['type'] = 'key establishment'
        thirdMessage['order'] = 3
        content = {}

        encodedNonce = asym_encrypt_from_file(nonce, SERVER_PUBLIC_KEY)
        signedNonce = sign(encodedNonce, self.client.key)

        content['message'] = base64.b64encode(encodedNonce)
        content['signature'] = base64.b64encode(signedNonce)

        thirdMessage['content'] = content

        return json.dumps(thirdMessage)

class Client():
    def __init__(self, username, password, key):
        self.key = key
        self.username = username
        self.password = password

    def connectToPeer(self, peer):
        connectionHandler = PeerConnectionHandler(self, peer)
        connectionHandler.run()


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
        # authenticationHandler.run()
        return Client(username, password, private_key)
    except Exception as err:
        print "authentication fail"
        print err


def main():
    login = False
    while True:
        currentClient = None
        if not login:
            currentClient = authenticate()

        command = raw_input(">> ")
        split = command.split()
        if split[0] == "list":
            pass
        elif split[0] == "connect":
            currentClient.connectToPeer(split[1])



###############################################################################
## Run program
###############################################################################
            
if __name__ == "__main__":
    main()

