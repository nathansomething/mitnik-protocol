import socket
import threading
import select
import time
import sys
import argparse
import json
import base64
import Queue

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
server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# This port is used to listen to peer
peerSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
peerSock.setblocking(0)
peerSockNumber = peerSock.getsockname()[1]

keepAlive = True
login = False

message_queue = Queue.Queue()
current_protocol = None
current_order = 0

authentication_handler = None
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
        while True:
            time.sleep(1)
            try:
                response = server_sock.recv(1024)
                decoded_response = json.loads(response)
                message_queue.put(decoded_response)
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
## Message Handler
###############################################################################
class MessageHandler(threading.Thread):
    def __init__(self, threadId, name, sock):
        threading.Thread.__init__(self)
        self.threadId = threadId
        self.name = name
        self.server_sock = sock
        pass

    def run(self):
        while True:
            if not message_queue.empty():
                message = message_queue.get()
                message_type = message['type']
                if message_type == 'error':
                    pass
                else:
                    if message_type == 'authentication':
                        self.handle_authentication_message(message)
                    elif message_type == 'key establishment':
                        self.handle_key_establishment_message(message)

    def handle_authentication_message(self, message):

        global authentication_handler

        if authentication_handler is None:
            raise Exception

        if message['order'] == 2:
            decoded_response = message

            content = decoded_response['content']
            content = base64.b64decode(content)

            decrypted_message_2 = json.loads(asym_decrypt(content, authentication_handler.key))
            if decrypted_message_2['nonce1'] == authentication_handler.nonce1:
                nonce2 = decrypted_message_2['nonce2']
                signed_nonce2 = sign(str(nonce2), authentication_handler.key)

                authentication_handler.nonce2 = nonce2

                third_message = authentication_handler.generate_third_authentication_message(signed_nonce2)

                self.server_sock.sendto(third_message, serverAddress)

        if message['order'] == 4:
            decoded_response = message

            content = decoded_response['content']
            verify(str(float(authentication_handler.nonce2)+1), base64.b64decode(content), SERVER_PUBLIC_KEY)

            global login
            login = True
            authentication_handler = None
            print "LOGIN SUCCESSFULLY"

    def handle_key_establishment_message(self, message):
        pass

    def handle_error_message(self, message):
        pass


###############################################################################
## Input listener
###############################################################################

class InputListener(threading.Thread):
    def __init__(self, threadId, name, sock):
        threading.Thread.__init__(self)
        self.threadId = threadId
        self.name = name
        self.sock = sock

    def run(self):
        global keepAlive
        while keepAlive:
            try:
                message = raw_input("> ")
            except (KeyboardInterrupt, SystemExit, EOFError):
                # kills all the thread when user hits ctrl+c
                keepAlive = False
                break

            except:
                break


###############################################################################
## Authentication Handler
###############################################################################
class AuthenticationHandler():
    def __init__(self, username, password, key):
        self.username = username
        self.password = password
        self.key = key
        self.nonce1 = None
        self.nonce2 = None

    def authenticate(self):
        nonce = gen_nonce()
        self.nonce1 = nonce
        first_message = \
            self.generate_first_authentication_message(self.username, self.password, nonce, self.key.public_key())

        server_sock.sendto(first_message, serverAddress)

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
        self.peer_public_key = ''

    def run(self):
        first_message = self.generate_first_message()
        server_sock.sendto(first_message, serverAddress)

        response = json.loads(server_sock.recv(1024))
        response_content = response['content']

        decrypted_response = asym_decrypt(base64.b64decode(response_content['message']), self.client.key)

        try:
            verify(decrypted_response, response_content['signature'], SERVER_PUBLIC_KEY)
        except Exception:
            print 'cannot get peer public key'

        decrypted_response_load = json.loads(decrypted_response)

        self.peer_public_key = load_public_key(str(decrypted_response_load['public_key']))
        nonce2 = decrypted_response_load['nonce2']

        third_message = self.generate_third_message(nonce2)

        server_sock.sendto(third_message, serverAddress)

        response = peerSock.recv(1024)

    def generate_first_message(self):
        first_message = {
            'type': 'key establishment',
            'order': 1
        }

        connection_info = {
            'peer': self.peer,
            'port': peerSockNumber
        }

        encoded_connection_info = asym_encrypt(json.dumps(connection_info), SERVER_PUBLIC_KEY)
        signed_username = sign(encoded_connection_info, self.client.key)

        content = {
            'message': base64.b64encode(encoded_connection_info),
            'signature': base64.b64encode(signed_username)
        }

        first_message['content'] = content

        return json.dumps(first_message)

    def generate_third_message(self, nonce):
        third_message = {
            'type': 'key establishment',
            'order': 3
        }

        encoded_nonce = asym_encrypt(nonce, SERVER_PUBLIC_KEY)
        signed_nonce = sign(encoded_nonce, self.client.key)

        content = {
            'message': base64.b64encode(encoded_nonce),
            'signature': base64.b64encode(signed_nonce)
        }

        third_message['content'] = content

        return json.dumps(third_message)


class Client():
    def __init__(self, username, password, key):
        self.key = key
        self.username = username
        self.password = password

    def connect_to_peer(self, peer):
        connection_handler = PeerConnectionHandler(self, peer)
        connection_handler.run()


###############################################################################
## Main functions
###############################################################################

def authenticate():
    global authentication_handler

    username = raw_input(">> Username: ")
    password = raw_input(">> Password: ")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )

    authentication_handler = AuthenticationHandler(username, password, private_key)
    try:
        authentication_handler.authenticate()
        return Client(username, password, private_key)
    except Exception as err:
        print "authentication fail"
        print err


def main():
    global login, keepAlive

    current_client = None

    server_listener = ServerListener(1, "server listener", server_sock)
    message_handler = MessageHandler(2, "message listener", server_sock)

    server_listener.daemon = True
    message_handler.daemon = True

    server_listener.start()
    message_handler.start()

    while keepAlive:
        try:
            if not login:
                current_client = authenticate()
                time.sleep(3)
                continue
            else:
                command = raw_input(">> ")
                split = command.split()
                if split[0] == "list":
                    pass
                elif split[0] == "connect":
                    current_client.connect_to_peer(split[1])

        except KeyboardInterrupt:
            # in case of exception we will kill all thread
            print "key board interrupt"
            keepAlive = False
            sys.exit()


###############################################################################
## Run program
###############################################################################
            
if __name__ == "__main__":
    try:
        main()
    except:
        # in case of exception we will kill all thread
        keepAlive = False
        sys.exit()

