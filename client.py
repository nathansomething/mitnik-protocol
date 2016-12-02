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

serverAddress = (serverIp, serverPort)

# This port is used to listen to the server
serverSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# This port is used to listen to peer
peerSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
peerSock.setblocking(0)
peerSockNumber = peerSock.getsockname()[1]

keepAlive = True
login = False

SERVER_PUBLIC_KEY = get_public_key('server_public_key.der')

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
                decoded_response = json.loads(response)
                msg_to_print = "<From {}:{}>: {}".format(decoded_response['ip'], decoded_response['port'], decoded_response['content'])
                print msg_to_print
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
        nonce = gen_nonce()
        first_message = \
            self.generate_first_authentication_message(self.username, self.password, nonce, self.key.public_key())

        serverSock.sendto(first_message, serverAddress)
        response = serverSock.recv(1024)
        decoded_response = json.loads(response)

        if decoded_response['type'] == 'authentication':
            content = decoded_response['content']
            content = base64.b64decode(content)

            decrypted_message_2 = json.loads(asym_decrypt(content, self.key))
            if decrypted_message_2['nonce1'] == nonce:
                nonce2 = decrypted_message_2['nonce2']
                signed_nonce2 = sign(str(nonce2), self.key)

                third_message = self.generate_third_authentication_message(signed_nonce2)

                serverSock.sendto(third_message, serverAddress)
                response = serverSock.recv(1024)

                decoded_response = json.loads(response)

                content = decoded_response['content']
                verify(str(float(nonce2)+1), base64.b64decode(content), SERVER_PUBLIC_KEY)
                global login
                login = True
                print "LOGIN SUCCESSFULLY"
            else:
                raise Exception("Wrong nonce")

        elif decoded_response['type'] == 'error':
            raise Exception("Wrong nonce")

    def generate_first_authentication_message(self, username, password, nonce, public_key):
        first_message = {
            'type': 'authentication',
            'order': 1
        }
        
        content = {
            'user': username,
            'password': password,
            'nonce': nonce,
            'publicKey': public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        }
        
        encoded_content = asym_encrypt(json.dumps(content), SERVER_PUBLIC_KEY)

        first_message["content"] = base64.b64encode(encoded_content)

        return json.dumps(first_message)

    def generate_third_authentication_message(self, signed_nonce):

        third_message = {
            'type': 'authentication',
            'order': 3,
            'content': {
                'sender': self.username,
                'signature': base64.b64encode(signed_nonce)
            }
        }

        return json.dumps(third_message)

class PeerConnectionHandler():
    def __init__(self, client, peer):
        # Username of the person we want to connect to
        self.peer = peer
        self.client = client

    def run(self):
        first_message = self.generate_first_message()
        print first_message

    def generate_first_message(self):
        first_message = {
            'type': 'key establishment',
            'order': 1
        }

        content = {}

        encodedUsername = asym_encrypt(self.peer, SERVER_PUBLIC_KEY)
        signedUsername = sign(encodedUsername, self.client.key)

        content['message'] = base64.b64encode(encodedUsername)
        content['signature'] = base64.b64encode(signedUsername)

        first_message['content'] = content

        return json.dumps(first_message)

    def generate_third_message(self, nonce):
        thirdMessage = {}
        thirdMessage['type'] = 'key establishment'
        thirdMessage['order'] = 3
        content = {}

        encodedNonce = asym_encrypt(nonce, SERVER_PUBLIC_KEY)
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
        authenticationHandler.run()
        return Client(username, password, private_key)
    except Exception as err:
        print "authentication fail"
        print err


def main():
    global login

    current_client = None
    while True:
        if not login:
            current_client = authenticate()

        command = raw_input(">> ")
        split = command.split()
        if split[0] == "list":
            pass
        elif split[0] == "connect":
            current_client.connectToPeer(split[1])



###############################################################################
## Run program
###############################################################################
            
if __name__ == "__main__":
    main()

