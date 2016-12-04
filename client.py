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

server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

keepAlive = True
login = False

message_queue = Queue.Queue()
current_protocol = None
current_order = 0

authentication_handler = None
current_client = None

SERVER_PUBLIC_KEY = get_public_key('server_public_key.der')


def send_signed_message(message, need_to_sign, address, sock):
    if current_client is not None:
        message['sender'] = current_client.username

    signature = ''
    if need_to_sign:
        signature = base64.b64encode(sign(json.dumps(message), current_client.key))

    packet = {
        'message': message,
        'signature': signature
    }

    sock.sendto(json.dumps(packet), address)


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
                message = packet[0]['message']
                signature = base64.b64decode(packet[0]['signature'])
                source_address = packet[1]
                message_type = message['type']
                if message_type == 'error':
                    pass
                else:
                    if message_type == 'authentication':
                        self.handle_authentication_message(message, source_address)
                    elif message_type == 'key establishment':
                        self.handle_key_establishment_message(message, signature, source_address)
                    elif message_type == 'list':
                        self.handle_list_message(message, source_address)

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

                send_signed_message(third_message, True, source_address, self.server_sock)

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

    def handle_key_establishment_message(self, message, signature, source_address):
        peer_key_establishment_handler = None
        if message['sender'] == 'server':
            if current_client.receiver in current_client.connections:
                peer_key_establishment_handler = \
                    current_client.connections[current_client.receiver].key_establishment_handler
        else:
            peer_key_establishment_handler = \
                current_client.connections[message['sender']].key_establishment_handler

        if message['sender'] == 'server':
            key_to_verify = SERVER_PUBLIC_KEY
        else:
            key_to_verify = peer_key_establishment_handler.peer_public_key

        if not verify(json.dumps(message), signature, key_to_verify):
            print 'receive message with wrong signature'
            return

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

            self.send_message(third_message, source_address)

        elif message['order'] == 4:
            content = message['content']

            packet = sym_decrypt(base64.b64decode(content['packet']), current_client.sym_key, current_client.iv)
            packet_load = json.loads(packet)

            user_request = packet_load['user_request']

            user_connection_info = packet_load['user_connection_info']

            sender_public_key = load_public_key(str(packet_load['sender_public_key']))
            nonce = packet_load['nonce']

            connection_info = PeerConnection()
            peer_key_establishment_handler = PeerConnectionHandler(current_client, user_request, None)
            peer_key_establishment_handler.peer_public_key = sender_public_key
            connection_info.key_establishment_handler = peer_key_establishment_handler
            current_client.connections[user_request] = connection_info

            fifth_message = peer_key_establishment_handler.generate_fifth_message(sender_public_key, nonce)

            connection_info_tuple = (str(user_connection_info[0]), user_connection_info[1])
            self.send_message(fifth_message, connection_info_tuple)

        elif message['order'] == 5:
            content = json.loads(asym_decrypt(base64.b64decode(message['content']), current_client.key))

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
                    'key': d_pub_key,
                    'signature': signed_key
                }
            }

            self.send_message(response, source_address)

        elif message['order'] == 6:
            content = message['content']
            sender = message['sender']

            key = content['key']

            signature = content['signature']

            verify(str(key), base64.b64decode(signature), peer_key_establishment_handler.peer_public_key)

            d = pyDH.DiffieHellman()
            d_pub_key = d.gen_public_key()

            shared_key = hash256(str(d.gen_shared_key(key)))

            current_client.connections[sender].key = shared_key

            nonce = gen_nonce()

            peer_key_establishment_handler.nonce3 = nonce

            signature = sign(str(nonce), current_client.key)

            response = {
                'type': 'key establishment',
                'order': 7,
                'content': {
                    'key': base64.b64encode(str(d_pub_key)),
                    'nonce': base64.b64encode(asym_encrypt(str(nonce), peer_key_establishment_handler.peer_public_key)),
                    'signature': base64.b64encode(signature)
                }
            }

            self.send_message(response, source_address)

        elif message['order'] == 7:
            content = message['content']
            key = long(base64.b64decode(content['key']))
            sender = message['sender']

            nonce = asym_decrypt(base64.b64decode(content['nonce']), current_client.key)
            verify(nonce, base64.b64decode(content['signature']), peer_key_establishment_handler.peer_public_key)

            shared_key = hash256(str(peer_key_establishment_handler.diffie_hellman.gen_shared_key(key)))
            iv = os.urandom(16)

            current_client.connections[sender].key = shared_key
            current_client.connections[sender].iv = iv

            encrypted_nonce = base64.b64encode(sym_encrypt(nonce, shared_key, iv))

            nonce4 = str(gen_nonce())
            peer_key_establishment_handler.nonce4 = nonce4

            response = {
                'type': 'key establishment',
                'order': 8,
                'content': {
                    'nonce3': encrypted_nonce,
                    'nonce4': nonce4,
                    'iv': base64.b64encode(
                        asym_encrypt(base64.b64encode(iv), peer_key_establishment_handler.peer_public_key)
                    )
                }
            }

            self.send_message(response, source_address)

        elif message['order'] == 8:
            content = message['content']
            sender = message['sender']
            iv = base64.b64decode(asym_decrypt(base64.b64decode(content['iv']), current_client.key))

            current_client.connections[sender].iv = iv

            nonce4 = content['nonce4']

            encrypted_nonce = base64.b64encode(
                sym_encrypt(str(nonce4),
                            current_client.connections[sender].key,
                            current_client.connections[sender].iv))

            response = {
                'type': 'key establishment',
                'order': 9,
                'content': {
                    'nonce': encrypted_nonce
                }
            }

            self.send_message(response, source_address)

        elif message['order'] == 9:
            content = message['content']
            sender = message['sender']

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
                    'message': base64.b64encode(encrypt_mes)
                }
            }

            self.send_message(response, source_address)

        elif message['order'] == 10:
            content = message['content']
            sender = message['sender']
            message = content['message']

            current_client.connections[sender].ip = source_address[0]
            current_client.connections[sender].port = source_address[1]

            decrypted_message = sym_decrypt(
                base64.b64decode(message), current_client.connections[sender].key, current_client.connections[sender].iv)

            print "from " + sender + ": " + decrypted_message
            sys.stdout.write(">> ")
            sys.stdout.flush()

    def send_message(self, message, source_address):
        send_signed_message(message, True, source_address, self.server_sock)

    def handle_list_message(self, message, source_address):
        user = message['users']
        print "user online: ", ", ".join(user)
        sys.stdout.write(">> ")
        sys.stdout.flush()

    def handle_error_message(self, message):
        pass


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

        send_signed_message(first_message, False, server_address, server_sock)

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

        return first_message

    def generate_third_authentication_message(self, signed_nonce):

        third_message = {
            'type': 'authentication',
            'order': 3,
            'content': {
                'sender': self.username,
                'signature': base64.b64encode(signed_nonce)
            }
        }

        return third_message


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
        send_signed_message(first_message, True, server_address, server_sock)

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

        return first_message

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

        return third_message

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

        return fifth_message


class ListHandler:
    def __init__(self):
        self.nonce = None

    def run(self):
        self.nonce = gen_nonce()

        message = {
            'type': 'list',
            'nonce': self.nonce
        }

        signature = sign(json.dumps(message), current_client.key)

        packet = {
            'type': 'list',
            'order': 0,
            'content': base64.b64encode(signature)
        }

        send_signed_message(packet, True, server_address, server_sock)


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
        self.receiver = None


class PeerConnection:
    def __init__(self):
        self.key_establishment_handler = None
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
                    list_handler = ListHandler()
                    list_handler.run()
                elif split[0] == "send":

                    if len(split) != 3:
                        print 'invalid command'

                    else:
                        mes = split[2]
                        receiver = split[1]
                        # if receiver in current_client.connections:
                        #     send_message(split[1], receiver)

                        current_client.receiver = receiver

                        connection = PeerConnection()
                        peer_key_establishment_handler = PeerConnectionHandler(current_client, receiver, mes)
                        connection.key_establishment_handler = peer_key_establishment_handler
                        current_client.connections[receiver] = connection

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

