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

with open(ROOT_DIR + '/server.json') as server_config_file:
        server_config_data = json.load(server_config_file)

server_tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    server_tcp_sock.connect((server_config_data['IP'], server_config_data['PORT']))

except:
    print "server is not ready"
    sys.exit()

peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peer_sock.bind(('', 0))
peer_sock.listen(10)

login = False

message_queue = Queue.Queue()
current_order = 0

authentication_handler = None
current_client = None

SERVER_PUBLIC_KEY = get_public_key(ROOT_DIR + '/server_public_key.der')

def send_message(message, need_to_sign, sock):
    if current_client is not None:
        message['sender'] = current_client.username

    signature = ''
    if need_to_sign:
        signature = base64.b64encode(sign(json.dumps(message), current_client.key))

    packet = {
        'message': message,
        'signature': signature
    }

    sock.sendall(json.dumps(packet))


###############################################################################
## Listener
###############################################################################
class MessageListener(threading.Thread):
    def __init__(self, threadId, name, sock):
        threading.Thread.__init__(self)
        self.threadId = threadId
        self.name = name
        self.sock = sock

    def run(self):
        while True:

            try:
                response, source_address = self.sock.recvfrom(4096)
                if response:
                    decoded_response = json.loads(response)
                    message_queue.put((decoded_response, source_address))
                else:
                    self.gracefully_exit()

            except ValueError:
                # server sends somthing that cannot be decoded:
                print "invalid message from server: ", response

            except Exception as e:
                if e.args[0] == 32:
                    self.gracefully_exit()

    def gracefully_exit(self):
        print self.name + ' has disconnected'
        sys.stdout.write(">> ")
        sys.stdout.flush()
        self.sock.close()
        sys.exit()


class PeerListener(threading.Thread):
    def __init__(self, threadId, name):
        threading.Thread.__init__(self)
        self.threadId = threadId
        self.name = name

    def run(self):

        while True:
            conn, addr = peer_sock.accept()
            conn.setblocking(0)

            current_client.connections[current_client.receiver].sock = conn
            peer_listener = MessageListener(0, current_client.receiver, conn)
            peer_listener.start()


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
                packet = message_queue.get()
                message = packet[0]['message']
                signature = base64.b64decode(packet[0]['signature'])
                source_address = packet[1]
                message_type = message['type']
                if message_type == 'error':
                    print message['content']
                    sys.stdout.write(">> ")
                    sys.stdout.flush()
                else:
                    try:
                        if message_type == 'authentication':
                            self.handle_authentication_message(message, source_address)
                        elif message_type == 'key establishment':
                            self.handle_key_establishment_message(message, signature, source_address)
                        elif message_type == 'list':
                            self.handle_list_message(message['content'], source_address)

                    except InvalidNonceException:
                        print 'receive invalid nonce from ' + message['sender']
                        sys.stdout.write(">> ")
                        sys.stdout.flush()

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

                third_message = authentication_handler.generate_third_message(signed_nonce2)

                send_message(third_message, True, self.server_sock)

        if message['order'] == 4:

            decoded_response = message

            content = decoded_response['content']
            verify(str(authentication_handler.nonce2[:-1]), base64.b64decode(content), SERVER_PUBLIC_KEY)

            global login
            login = True
            authentication_handler = None

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
                base64.b64decode(content),
                peer_key_establishment_handler.client.sym_key,
                peer_key_establishment_handler.client.iv)

            packet_json = json.loads(packet)

            verify(json.dumps(message), signature, SERVER_PUBLIC_KEY)

            peer_key_establishment_handler.peer_public_key = load_public_key(str(packet_json['requested_public_key']))
            nonce = packet_json['nonce']

            third_message = peer_key_establishment_handler.generate_third_message(nonce)
            peer_key_establishment_handler.nonce = nonce

            send_message(third_message, True, server_tcp_sock)

        elif message['order'] == 4:

            content = message['content']

            packet = sym_decrypt(base64.b64decode(content), current_client.sym_key, current_client.iv)
            packet_load = json.loads(packet)

            user_request = packet_load['user_request']

            user_connection_info = packet_load['user_connection_info']
            connection_info_tuple = (str(user_connection_info[0]), user_connection_info[1])

            new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            new_socket.connect(connection_info_tuple)

            sender_public_key = load_public_key(str(packet_load['sender_public_key']))
            nonce = packet_load['nonce']

            connection_info = PeerConnection()
            connection_info.sock = new_socket

            server_listener = MessageListener(1, user_request, new_socket)
            server_listener.start()

            peer_key_establishment_handler = PeerConnectionHandler(current_client, user_request, None)
            peer_key_establishment_handler.peer_public_key = sender_public_key
            connection_info.key_establishment_handler = peer_key_establishment_handler
            current_client.connections[user_request] = connection_info

            fifth_message = peer_key_establishment_handler.generate_fifth_message(sender_public_key, nonce)

            send_message(fifth_message, True, new_socket)

        elif message['order'] == 5:
            sender = message['sender']
            content = json.loads(asym_decrypt(base64.b64decode(message['content']), current_client.key))
            nonce = content['nonce']

            str(nonce) == str(peer_key_establishment_handler.nonce)

            d = pyDH.DiffieHellman()
            d_pub_key = d.gen_public_key()

            peer_key_establishment_handler.diffie_hellman = d
            signed_key = base64.b64encode(sign(str(d_pub_key), current_client.key))

            response = construct_msg(
                'key establishment',
                6,
                {
                    'key': d_pub_key,
                    'signature': signed_key
                }
            )

            send_message(response, True, current_client.connections[sender].sock)

        elif message['order'] == 6:
            content = message['content']
            sender = message['sender']
            key = content['key']
            signature = content['signature']

            if not verify(str(key),
                      base64.b64decode(signature),
                      peer_key_establishment_handler.peer_public_key):
              print "Verification Failed"
              return

            d = pyDH.DiffieHellman()
            d_pub_key = d.gen_public_key()
            shared_key = hash256(str(d.gen_shared_key(key)))
            current_client.connections[sender].key = shared_key
            nonce = gen_nonce()
            peer_key_establishment_handler.nonce3 = nonce
            signature = sign(str(nonce), current_client.key)

            response = construct_msg(
                'key establishment',
                7,
                {
                    'key': base64.b64encode(str(d_pub_key)),
                    'nonce': base64.b64encode(asym_encrypt(str(nonce), peer_key_establishment_handler.peer_public_key)),
                    'signature': base64.b64encode(signature)
                }
            )

            send_message(response, True, current_client.connections[sender].sock)

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

            send_message(response, True, current_client.connections[sender].sock)

        elif message['order'] == 8:
            content = message['content']
            sender = message['sender']

            iv = base64.b64decode(asym_decrypt(base64.b64decode(content['iv']), current_client.key))

            current_client.connections[sender].iv = iv
            nonce3 = sym_decrypt(base64.b64decode(content['nonce3']), current_client.connections[sender].key, iv)

            if nonce3 != peer_key_establishment_handler.nonce3:
                raise InvalidNonceException("receive invalid nonce")

            nonce4 = content['nonce4']
            peer_key_establishment_handler.nonce4 = nonce4

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

            send_message(response, True, current_client.connections[sender].sock)

        elif message['order'] == 9:
            content = message['content']
            sender = message['sender']

            nonce4 = sym_decrypt(base64.b64decode(content['nonce']),
                                 current_client.connections[sender].key,
                                 current_client.connections[sender].iv)

            if nonce4 != peer_key_establishment_handler.nonce4:
                raise InvalidNonceException("receive invalid nonce")

            mes = peer_key_establishment_handler.message

            encrypt_mes = sym_encrypt(mes,
                                      current_client.connections[sender].key,
                                      current_client.connections[sender].iv)

            response = {
                'type': 'key establishment',
                'order': 10,
                'content': {
                    'message': base64.b64encode(encrypt_mes)
                }
            }

            send_message(response, True, current_client.connections[sender].sock)

        elif message['order'] == 10:
            content = message['content']
            sender = message['sender']
            message = content['message']

            decrypted_message = sym_decrypt(
                base64.b64decode(message), current_client.connections[sender].key, current_client.connections[sender].iv)

            print "from " + sender + ": " + decrypted_message
            sys.stdout.write(">> ")
            sys.stdout.flush()

    def handle_list_message(self, content, source_address):
        nonce = str(asym_decrypt(base64.b64decode(content['nonce']), current_client.key))

        if nonce != current_client.list_nonce[:-1]:
            raise InvalidNonceException('invalid nonce')

        current_client.list_nonce = None

        print "user online: ", ", ".join(content['users'])
        sys.stdout.write(">> ")
        sys.stdout.flush()

    def handle_error_message(self, message):
        pass


###############################################################################
## Authentication Handler
###############################################################################

# Handels the authentication portion of the Mitnick Protocol
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
        self.nonce1 = gen_nonce()
        first_message = self.generate_first_message(self.key.public_key())
        send_message(first_message, False, server_tcp_sock)

    def get_encrypted_key(self, public_key):
        public_key_byte = public_key.public_bytes(
                            serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)

        return base64.b64encode(
            sym_encrypt(
                public_key_byte, self.sym_key, self.iv))

    # Generates the initial message from the client, instructing the server
    # to register as active. This allows the client to send messages to
    # other clinets
    def generate_first_message(self, public_key):

        return construct_msg(
            'authentication',
            1,
            {
                'packet': base64.b64encode(asym_encrypt(json.dumps({
                    'user': self.username,
                    'password': self.password,
                    'nonce': self.nonce1,
                    'sym_key': base64.b64encode(self.sym_key),
                    'iv': base64.b64encode(self.iv)
                }), SERVER_PUBLIC_KEY)),
                'key': self.get_encrypted_key(public_key)
            }
        )

    # Confirms to the Server that the client recieved it's message,
    # and knows that it's been activated
    def generate_third_message(self, signed_nonce):

        return construct_msg(
            'authentication',
            3,
            {
                'sender': self.username,
                'signature': base64.b64encode(signed_nonce)
            }
        )

# Handels P2P connections between clients
class PeerConnectionHandler():
    def __init__(self, client, peer, message):
        # Username of the person we want to connect to
        self.peer = peer
        self.client = client
        self.peer_public_key = None
        self.d_public_key = None
        self.nonce = None
        self.nonce3 = None
        self.nonce4 = None
        self.diffie_hellman = None
        self.message = message

    def run(self):
        first_message = self.generate_first_message()
        send_message(first_message, True, server_tcp_sock)

    def generate_first_message(self):

        return construct_msg(
            'key establishment',
            1,
            base64.b64encode(asym_encrypt(json.dumps({
                'sender': self.client.username,
                'receiver': self.peer,
                'address': current_client.connection_info
            }),SERVER_PUBLIC_KEY))
        )

    def generate_third_message(self, nonce):

        signed_nonce = sign(str(nonce), self.client.key)
        return construct_msg(
            'key establishment',
            3,
            {
                'sender': self.client.username,
                'signature': base64.b64encode(signed_nonce)
            }
        )

    def generate_fifth_message(self, public_key, nonce):
        return construct_msg(
            'key establishment',
            5,
            base64.b64encode(asym_encrypt(json.dumps({
                'sender': current_client.username,
                'nonce': nonce
            }), public_key))
        )

# Handles the List protocol
class ListHandler:
    def __init__(self):
        pass

    def run(self):
        nonce = gen_nonce()
        current_client.list_nonce = nonce

        message = construct_msg(
            'list',
            0,
            {
                'nonce': base64.b64encode(asym_encrypt(nonce, SERVER_PUBLIC_KEY)),
                'user': current_client.username
            }
        )

        send_message(message, True, server_tcp_sock)


class Client:
    def __init__(self, username, password, key, sym_key, iv):
        # the private key for this session
        self.key = key
        self.username = username
        self.password = password

        # the symmetric key that is used to communicate with the server
        self.sym_key = sym_key
        self.iv = iv

        self.connection_info = ('127.0.0.1', peer_sock.getsockname()[1])

        # username (str) -> PeerConnection
        self.connections = {}

        self.list_nonce = None

        self.receiver = None


# Essentially a wrapper for PeerConnectionHandler that also include connection information
class PeerConnection:
    def __init__(self):
        self.key_establishment_handler = None
        self.key = None
        self.iv = None
        self.ip = None
        self.port = None
        self.sock = None


class InvalidNonceException(Exception):
    def __init__(self, message):
        self.message = message


###############################################################################
## Main functions
###############################################################################

def authenticate():
    global authentication_handler
    username = raw_input(">> Username: ")
    password = raw_input(">> Password: ")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    authentication_handler = AuthenticationHandler(username, password, private_key)

    print 'waiting for server response'
    authentication_handler.authenticate()
    return Client(username, password, private_key, authentication_handler.sym_key, authentication_handler.iv)


def main():
    global login, current_client

    server_listener = MessageListener(1, "server", server_tcp_sock)
    message_handler = MessageHandler(2, "message listener", server_tcp_sock)
    peer_listener = PeerListener(3, "peer listener")

    server_listener.daemon = True
    message_handler.daemon = True
    peer_listener.daemon = True

    server_listener.start()
    message_handler.start()
    peer_listener.start()

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

                    if len(split) < 3:
                        print 'invalid command'

                    else:
                        mes = ' '.join(split[2:])
                        receiver = split[1]
                        # if receiver in current_client.connections:
                        #     send_message(split[1], receiver)

                        current_client.receiver = receiver

                        connection = PeerConnection()
                        peer_key_establishment_handler = PeerConnectionHandler(current_client, receiver, mes)
                        connection.key_establishment_handler = peer_key_establishment_handler
                        current_client.connections[receiver] = connection

                        peer_key_establishment_handler.run()
                else:
                    print 'invalid command'

        except KeyboardInterrupt:
            # in case of exception we will kill all thread
            print "key board interrupt"
            sys.exit()


###############################################################################
## Run program
###############################################################################

if __name__ == "__main__":
    main()
