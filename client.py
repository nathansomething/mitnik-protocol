import socket
import threading
import select
import time
import sys
import argparse
import json
import base64
import Queue
import os
import pyDH

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

server_address = (serverIp, serverPort)

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
peer_key_establishment_handler = None
current_client = None

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
            response, source_address = server_sock.recvfrom(4096)
            try:

                decoded_response = json.loads(response)

                # print 'recv: '
                # print response
                message_queue.put((decoded_response, source_address))
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
        global current_protocol
        while True:
            if not message_queue.empty():
                packet = message_queue.get()
                message = packet[0]
                source_address = packet[1]
                message_type = message['type']
                if message_type == 'error':
                    pass
                else:
                    if message_type == 'authentication':
                        self.handle_authentication_message(message, source_address)
                    elif message_type == 'key establishment':
                        self.handle_key_establishment_message(message, source_address)

    def handle_authentication_message(self, message, source_address):

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

                self.server_sock.sendto(third_message, server_address)

        if message['order'] == 4:
            decoded_response = message

            content = decoded_response['content']
            verify(str(authentication_handler.nonce2[:-1]), base64.b64decode(content), SERVER_PUBLIC_KEY)

            global login
            login = True
            authentication_handler = None

            global current_protocol
            current_protocol = 'key establishment'
            print "login successfully"

    def handle_key_establishment_message(self, message, source_address):
        global peer_key_establishment_handler
        if peer_key_establishment_handler is None and message['order'] != 4:
            raise Exception

        if message['order'] == 2:
            content = message['content']

            packet = sym_decrypt(
                base64.b64decode(content['packet']),
                peer_key_establishment_handler.client.sym_key,
                peer_key_establishment_handler.client.iv)

            packet_json = json.loads(packet)

            verify(str(packet_json['nonce']), base64.b64decode(content['signature']), SERVER_PUBLIC_KEY)

            peer_key_establishment_handler.peer_public_key = load_public_key(str(packet_json['requested_public_key']))
            nonce = packet_json['nonce']

            third_message = peer_key_establishment_handler.generate_third_message(nonce)
            peer_key_establishment_handler.nonce = nonce

            self.server_sock.sendto(third_message, server_address)

        elif message['order'] == 4:

            content = message['content']
            packet = sym_decrypt(base64.b64decode(content['packet']), current_client.sym_key, current_client.iv)
            packet_load = json.loads(packet)

            user_request = packet_load['user_request']
            user_connection_info = packet_load['user_connection_info']

            sender_public_key = load_public_key(str(packet_load['sender_public_key']))
            nonce = packet_load['nonce']

            peer_key_establishment_handler = PeerConnectionHandler(current_client, user_request, None)
            peer_key_establishment_handler.peer_public_key = sender_public_key

            fifth_message = peer_key_establishment_handler.generate_fifth_message(sender_public_key, nonce)

            connection_info_tuple = (str(user_connection_info[0]), user_connection_info[1])
            self.server_sock.sendto(fifth_message, connection_info_tuple)

        elif message['order'] == 5:
            content = json.loads(asym_decrypt(base64.b64decode(message['content']), current_client.key))

            sender = content['sender']
            nonce = content['nonce']

            str(nonce) == str(peer_key_establishment_handler.nonce)

            d = pyDH.DiffieHellman()
            d_pub_key = d.gen_public_key()

            peer_key_establishment_handler.diffie_hellman = d
            signed_key = base64.b64encode(sign(str(d_pub_key), current_client.key))

            response = {
                'type': 'key establishment',
                'order': 6,
                'content': {
                    'sender': current_client.username,
                    'key': d_pub_key,
                    'signature': signed_key
                }
            }

            self.server_sock.sendto(json.dumps(response), source_address)

        elif message['order'] == 6:

            content = message['content']
            sender = content['sender']

            key = content['key']

            signature = content['signature']

            verify(str(key), base64.b64decode(signature), peer_key_establishment_handler.peer_public_key)

            d = pyDH.DiffieHellman()
            d_pub_key = d.gen_public_key()

            shared_key = hash256(str(d.gen_shared_key(key)))

            connection_info = PeerConnection()
            connection_info.key = shared_key
            current_client.connections[sender] = connection_info

            nonce = gen_nonce()

            peer_key_establishment_handler.nonce3 = nonce

            signature = sign(str(nonce), current_client.key)

            response = {
                'type': 'key establishment',
                'order': 7,
                'content': {
                    'sender': current_client.username,
                    'key': base64.b64encode(str(d_pub_key)),
                    'nonce': base64.b64encode(asym_encrypt(str(nonce), peer_key_establishment_handler.peer_public_key)),
                    'signature': base64.b64encode(signature)
                }
            }

            self.server_sock.sendto(json.dumps(response), source_address)

        elif message['order'] == 7:
            content = message['content']
            key = long(base64.b64decode(content['key']))
            sender = content['sender']

            nonce = asym_decrypt(base64.b64decode(content['nonce']), current_client.key)
            verify(nonce, base64.b64decode(content['signature']), peer_key_establishment_handler.peer_public_key)

            shared_key = hash256(str(peer_key_establishment_handler.diffie_hellman.gen_shared_key(key)))
            iv = os.urandom(16)

            connection = PeerConnection()
            connection.key = shared_key
            connection.iv = iv
            current_client.connections[sender] = connection

            encrypted_nonce = base64.b64encode(sym_encrypt(nonce, shared_key, iv))

            nonce4 = str(gen_nonce())
            peer_key_establishment_handler.nonce4 = nonce4

            response = {
                'type': 'key establishment',
                'order': 8,
                'content': {
                    'sender': current_client.username,
                    'nonce3': encrypted_nonce,
                    'nonce4': nonce4,
                    'iv': base64.b64encode(
                        asym_encrypt(base64.b64encode(iv), peer_key_establishment_handler.peer_public_key)
                    )
                }
            }

            self.server_sock.sendto(json.dumps(response), source_address)

        elif message['order'] == 8:
            content = message['content']
            sender = content['sender']
            iv = base64.b64decode(asym_decrypt(base64.b64decode(content['iv']), current_client.key))

            current_client.connections[sender].iv = iv

            nonce3 = sym_decrypt(
                base64.b64decode(content['nonce3']),
                current_client.connections[sender].key,
                current_client.connections[sender].iv
            )

            nonce4 = content['nonce4']

            encrypted_nonce = base64.b64encode(
                sym_encrypt(str(nonce4),
                            current_client.connections[sender].key,
                            current_client.connections[sender].iv))

            response = {
                'type': 'key establishment',
                'order': 9,
                'content': {
                    'sender': current_client.username,
                    'nonce': encrypted_nonce
                }
            }

            self.server_sock.sendto(json.dumps(response), source_address)

        elif message['order'] == 9:
            content = message['content']
            sender = content['sender']
            nonce = content['nonce']

            mes = peer_key_establishment_handler.message

            encrypt_mes = sym_encrypt(mes,
                                      current_client.connections[sender].key,
                                      current_client.connections[sender].iv)

            current_client.connections[sender].ip = source_address[0]
            current_client.connections[sender].port = source_address[1]

            response = {
                'type': 'key establishment',
                'order': 10,
                'content': {
                    'sender': current_client.username,
                    'message': base64.b64encode(encrypt_mes)
                }
            }

            self.server_sock.sendto(json.dumps(response), source_address)

        elif message['order'] == 10:
            content = message['content']
            sender = content['sender']
            message = content['message']

            current_client.connections[sender].ip = source_address[0]
            current_client.connections[sender].port = source_address[1]

            decrypted_message = sym_decrypt(
                base64.b64decode(message), current_client.connections[sender].key, current_client.connections[sender].iv)

            print "from " + sender + ": " + decrypted_message
            sys.stdout.write(">> ")
            sys.stdout.flush()

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
        self.sym_key = os.urandom(32)
        self.iv = os.urandom(16)

    def authenticate(self):
        nonce = gen_nonce()
        self.nonce1 = nonce
        first_message = \
            self.generate_first_authentication_message(self.username, self.password, nonce, self.key.public_key())

        server_sock.sendto(first_message, server_address)

    def generate_first_authentication_message(self, username, password, nonce, public_key):
        first_message = {
            'type': 'authentication',
            'order': 1
        }
        
        content = {
            'user': username,
            'password': password,
            'nonce': nonce,
            'sym_key': base64.b64encode(self.sym_key),
            'iv': base64.b64encode(self.iv)
        }

        public_key_byte = public_key.public_bytes(
                            serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo
                        )

        encrypted_key = base64.b64encode(
            sym_encrypt(
                public_key_byte, self.sym_key, self.iv))

        encoded_content = base64.b64encode(asym_encrypt(json.dumps(content), SERVER_PUBLIC_KEY))

        first_message["content"] = {
            'packet': encoded_content,
            'key': encrypted_key
        }

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
    def __init__(self, client, peer, message):
        # Username of the person we want to connect to
        self.peer = peer
        self.client = client
        self.peer_public_key = None
        self.d_public_key = None
        self.nonce = None

        self.peer_nonce3 = None
        self.nonce4 = None

        self.diffie_hellman = None

        self.message = message

    def run(self):
        first_message = self.generate_first_message()
        server_sock.sendto(first_message, server_address)

    def generate_first_message(self):
        first_message = {
            'type': 'key establishment',
            'order': 1
        }

        connection_info = {
            'sender': self.client.username,
            'receiver': self.peer
        }

        encoded_connection_info = \
            base64.b64encode(asym_encrypt(json.dumps(connection_info), SERVER_PUBLIC_KEY))
        # signed_username = sign(encoded_connection_info, self.client.key)

        content = {
            'connection_info': encoded_connection_info
        }

        first_message['content'] = content

        return json.dumps(first_message)

    def generate_third_message(self, nonce):
        third_message = {
            'type': 'key establishment',
            'order': 3
        }

        signed_nonce = sign(str(nonce), self.client.key)

        content = {
            'sender': self.client.username,
            'signature': base64.b64encode(signed_nonce)
        }

        third_message['content'] = content

        return json.dumps(third_message)

    def generate_fifth_message(self, public_key, nonce):
        fifth_message = {
            'type': 'key establishment',
            'order': 5,

        }

        content = {
            'sender': current_client.username,
            'nonce': nonce
        }

        content_byte = base64.b64encode(asym_encrypt(json.dumps(content), public_key))
        fifth_message['content'] = content_byte

        return json.dumps(fifth_message)


class ListHandler:
    def __init__(self):
        self.nonce = None

    def run(self):
        self.nonce = gen_nonce()

        message = {
            'type': 'list'
        }
        packet = {
            'message': '',
            'signature': ''
        }

class Client:
    def __init__(self, username, password, key, sym_key, iv):
        self.key = key
        self.username = username
        self.password = password
        self.sym_key = sym_key
        self.iv = iv

        self.connection_info = ('127.0.0.1', server_sock.getsockname()[1])
        self.connections = {}
        self.session_keys = {}


class PeerConnection:
    def __init__(self):
        self.key = None
        self.iv = None
        self.ip = None
        self.port = None


###############################################################################
## Main functions
###############################################################################

def authenticate():
    global authentication_handler, current_protocol
    username = raw_input(">> Username: ")
    password = raw_input(">> Password: ")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    current_protocol = 'authentication'
    authentication_handler = AuthenticationHandler(username, password, private_key)
    try:
        print 'waiting for server response'
        authentication_handler.authenticate()
        return Client(username, password, private_key, authentication_handler.sym_key, authentication_handler.iv)
    except Exception as err:
        print "authentication fail"
        print err


def send_message(mes, receiver):
    key = current_client[receiver].key
    iv = current_client[receiver].iv
    ip = current_client[receiver].ip
    port = current_client[receiver].port

    encrypt_mes = sym_encrypt(mes, key, iv)

    response = {
        'type': 'key establishment',
        'order': 10,
        'content': {
            'sender': current_client.username,
            'message': base64.b64encode(encrypt_mes)
        }
    }

    server_sock.sendto(json.dumps(response), (ip, port))


def main():
    global login, keepAlive, current_client

    server_listener = ServerListener(1, "server listener", server_sock)
    message_handler = MessageHandler(2, "message listener", server_sock)

    server_listener.daemon = True
    message_handler.daemon = True

    server_listener.start()
    message_handler.start()

    while True:
        try:
            if not login:
                current_client = authenticate()
                time.sleep(2)
                continue
            else:
                command = raw_input(">> ")
                split = command.split()
                if split[0] == "list":
                    pass
                elif split[0] == "send":
                    global peer_key_establishment_handler

                    if len(split) != 3:
                        print 'invalid command'

                    else:
                        receiver = split[2]

                        # if receiver in current_client.connections:
                        #     send_message(split[1], receiver)

                        peer_key_establishment_handler = PeerConnectionHandler(current_client, split[1], receiver)
                        peer_key_establishment_handler.run()

        except KeyboardInterrupt:
            # in case of exception we will kill all thread
            print "key board interrupt"
            keepAlive = False
            sys.exit()


###############################################################################
## Run program
###############################################################################
            
if __name__ == "__main__":
    main()

