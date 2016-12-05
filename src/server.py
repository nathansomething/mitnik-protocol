import socket
from util import *
import base64
from thread import *

import sys
from cryptography.hazmat.primitives import serialization


PUBLIC_KEY = get_public_key(ROOT_DIR + '/server_public_key.der')
PRIVATE_KEY = get_private_key(ROOT_DIR + '/server_private_key.der')

clients = {}
connections = {}
client_pairs = []

###############################################################################
## Client info
###############################################################################

# Contains information about each client
class ClientInfo:

    def __init__(self, password):
        self.password = password
        self.connection_info = None
        self.authentication_nonce = None
        self.active = False
        self.public_key = ''
        self.key_establishment_nonce = None
        self.peer_connection_info = None
        self.peer = None
        self.sym_key = None
        self.iv = None
        self.sock = None

    def pair_with(self, peer):
        self.peer = peer

    def login(self):
        self.active = True

    def isActive(self):
        return self.isActive()


def send_signed_message(message, need_to_sign, sock):
    message['sender'] = 'server'

    signature = ''
    if need_to_sign:
        signature = base64.b64encode(sign(json.dumps(message), PRIVATE_KEY))

    packet = {
        'message': message,
        'signature': signature
    }

    sock.sendall(json.dumps(packet))


# Authenticates a client's username and password to determine if the
# match the records stored on the server
def authenticate(username, password):
    if username in clients:
        return password == clients[username].password
    else:
        return False


# Returns the account's active users
def get_active_users():
    active = []
    for client in clients:
        if clients[client].active:
            active.append(client)

    return active


# Updates the credentials of the client corresponding
# to the given username
def update_user(username, source_ip, public_key, nonce, key, iv):
    client = clients[username]
    client.source_ip = source_ip
    client.public_key = public_key
    client.authentication_nonce = str(nonce)
    client.sym_key = key
    client.iv = iv


# Sends an error message to the client if something goes wrong
def send_error_message(sock, addr):
    nonce = str(gen_nonce())
    error_message = \
        {
            'type': 'error',
            'message': nonce
        }

    send_signed_message(error_message, True, sock)


# Authenticate the user with the server
def authentication(order, content, client_address, sock):
    if order == 1:
        # Read client packet
        packet = content['packet']
        key = content['key']

        decoded_content = asym_decrypt(base64.b64decode(packet), PRIVATE_KEY)
        content = json.loads(decoded_content)
        username = content['user']
        password = content['password']
        nonce = content['nonce']

        sym_key = base64.b64decode(content['sym_key'])
        iv = base64.b64decode(content['iv'])

        # Generate a new nonce
        nonce2 = gen_nonce()

        # Make sure the client has a valid username and password
        if authenticate(username, password):
            # Update the active user log
            pub_key_byte = sym_decrypt(base64.b64decode(key), sym_key, iv)
            pub_key = load_public_key(pub_key_byte)
            update_user(username, client_address, pub_key, nonce2, sym_key, iv)
            response = construct_msg(
                'authentication',
                2,
                base64.b64encode(
                    asym_encrypt(
                        json.dumps({
                            'nonce1': nonce,
                            'nonce2': nonce2
                        }), pub_key))
            )
            send_signed_message(response, True, sock)
        else:
            send_error_message(sock, client_address)

    elif order == 3:
        signature = base64.b64decode(content['signature'])
        sender = content['sender']
        client = clients[sender]
        nonce = client.authentication_nonce
        if verify(nonce, signature, client.public_key):
            response = construct_msg(
                'authentication',
                4,
                base64.b64encode(sign(nonce[:-1], PRIVATE_KEY))
            )

            clients[sender].active = True

            # if clients[sender].sock is not None:
            #     clients[sender].sock.close()

            clients[sender].sock = sock

            print 'client ' + sender + ' has logged in'

            send_signed_message(response, True, sock)
        else:
            send_error_message(sock, client_address)
    else:
        send_error_message(sock, client_address)


# Establish a shared key between two clients
def establishment(order, content, source_ip, sock):

    if order == 1:

        # Decrypt connection information coming from the client
        content = json.loads(asym_decrypt(
                                base64.b64decode(content),PRIVATE_KEY))
        debug("Connection Info", content)

        clients[content['sender']].connection_info = content['address']

        sender_public_key = clients[content['sender']].public_key
        receiver_public_key = clients[content['receiver']].public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if receiver_public_key:
            nonce = str(gen_nonce())
            clients[content['sender']].key_establishment_nonce = nonce
            clients[content['sender']].peer_connection_info = clients[content['receiver']].connection_info
            clients[content['receiver']].peer_connection_info = clients[content['sender']].connection_info

            clients[content['sender']].peer = content['receiver']
            clients[content['receiver']].peer = content['sender']

            response = construct_msg(
                'key establishment',
                2,
                {
                    'packet': base64.b64encode(sym_encrypt(json.dumps({
                                            'requested_public_key': receiver_public_key,
                                            'nonce': nonce
                                        }),
                                        clients[content['sender']].sym_key,
                                        clients[content['sender']].iv)),
                    'signature': base64.b64encode(sign(nonce, PRIVATE_KEY))
                }
            )
        else:
            response = construct_msg(
                'error',
                0,
                content=asym_encrypt(json.dumps({
                    'message': 'Public Key Not Found'
                }), sender_public_key)
            )

        send_signed_message(response, True, sock)

    elif order == 3:
        sender = content['sender']
        sender_public_key = clients[content['sender']].public_key
        sender_nonce = clients[content['sender']].key_establishment_nonce

        receiver = clients[content['sender']].peer
        if verify(str(sender_nonce),
                  base64.b64decode(content['signature']),
                  sender_public_key):

            packet = base64.b64encode(
                        sym_encrypt(json.dumps({
                            'user_request': content['sender'],
                            'user_connection_info': clients[content['sender']].connection_info,
                            'sender_public_key': sender_public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            ),
                            'nonce': sender_nonce,
                        }),
                        clients[receiver].sym_key,
                        clients[receiver].iv)
                    )

            response = construct_msg(
                'key establishment',
                4,
                {
                    'packet': packet,
                    'signature': base64.b64encode(sign(packet, PRIVATE_KEY))
                }
            )

            send_signed_message(response,
                                True,
                                clients[clients[content['sender']].peer].sock)

        else:
            print 'key establishment has failed'
            # response = construct_msg(
            #     'error',
            #     0,
            #     asym_encrypt(json.dumps({
            #         'message': 'Signature Verification Failed'
            #     }), public_key))
            # socket.send(response, client_ip)


# Returns the users currently active on the server
def list_user(order, content, source_ip, sock):

    user = content['user']
    if not clients[user].active:
        return

    nonce = asym_decrypt(base64.b64decode(content['nonce']), PRIVATE_KEY)
    active_users = get_active_users()
    response = {
        'type': 'list',
        'nonce': base64.b64encode(asym_encrypt(nonce[:-1], clients[user].public_key)),
        'users': active_users
    }

    send_signed_message(response, True, sock)


def message():
    pass

# Message type categories to send to
message_types = {
    'authentication': authentication,
    'key establishment': establishment,
    'list': list_user
    # "message": message,
    # "logout": logout
}


def client_thread(conn):

    while True:
        try:
            data, client_address = conn.recvfrom(4096)

            # Load client data as JSON
            client_packet = json.loads(data)['message']
            # Route the message based on type
            message_types[client_packet['type']](
                client_packet['order'],
                client_packet['content'],
                client_address, conn)

        except ValueError as e:
            print e
            for client in clients:
                if clients[client].sock == conn:
                    clients[client].active = False

                    print client + ' has disconnected'

            break

        except Exception as e:
            if e.args[0] == 35:
                pass
            else:
                print e

    conn.close()


def main():
    print "Server Initialized..."

    with open(ROOT_DIR + '/server.json') as server_config_file:
        server_config_data = json.load(server_config_file)

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.bind((server_config_data['IP'], server_config_data['PORT']))

    tcp_sock.listen(10)

    with open(ROOT_DIR + '/users.json') as user_config:
        users = json.load(user_config)
        for username in users:
            client = ClientInfo(users[username])
            clients[username] = client

    with open(ROOT_DIR + '/users.json') as user_config:
        users = json.load(user_config)
        for username in users:
            client = ClientInfo(users[username])
            clients[username] = client

    while True:
        conn, addr = tcp_sock.accept()
        #conn.setblocking(0)
        print 'Connected with ' + addr[0] + ':' + str(addr[1])

        start_new_thread(client_thread, (conn,))




if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        sys.exit()