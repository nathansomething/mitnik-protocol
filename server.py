import socket
from util import *
import base64
from thread import *

from cryptography.hazmat.primitives import serialization


PUBLIC_KEY = get_public_key('server_public_key.der')
PRIVATE_KEY = get_private_key('server_private_key.der')

PORT = 9999

clients = {}
connections = {}
client_pairs = []


###############################################################################
## Client info
###############################################################################

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


def authenticate(username, password):
    if username in clients:
        return password == clients[username].password
    else:
        return False


def get_active_user():
    active = []
    for client in clients:
        if clients[client].active:
            active.append(client)

    return active


def update_user(username, source_ip, public_key, nonce, key, iv):
    client = clients[username]
    client.source_ip = source_ip
    client.public_key = public_key
    client.authentication_nonce = str(nonce)
    client.sym_key = key
    client.iv = iv


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
        # Read Client Packet

        connection_info = content['connection_info']

        decrypted_connection_info = \
            json.loads(asym_decrypt(base64.b64decode(connection_info), PRIVATE_KEY))

        sender = decrypted_connection_info['sender']
        receiver = decrypted_connection_info['receiver']
        address = decrypted_connection_info['address']

        clients[sender].connection_info = address

        sender_public_key = clients[sender].public_key
        receiver_public_key = clients[receiver].public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if receiver_public_key:
            nonce = str(gen_nonce())
            clients[sender].key_establishment_nonce = nonce
            clients[sender].peer_connection_info = clients[receiver].connection_info
            clients[receiver].peer_connection_info = clients[sender].connection_info

            clients[sender].peer = receiver
            clients[receiver].peer = sender

            packet = {
                'requested_public_key': receiver_public_key,
                'nonce': nonce
            }

            encrypted_packet = \
                base64.b64encode(sym_encrypt(json.dumps(packet), clients[sender].sym_key, clients[sender].iv))

            response = construct_msg(
                'key establishment',
                2,
                {
                    'packet': encrypted_packet,
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
        sender_public_key = clients[sender].public_key
        sender_nonce = clients[sender].key_establishment_nonce
        signature = content['signature']

        receiver = clients[sender].peer
        if verify(str(sender_nonce), base64.b64decode(signature), sender_public_key):
            to_encrypt = json.dumps({
                            'user_request': sender,
                            'user_connection_info': clients[sender].connection_info,
                            'sender_public_key': sender_public_key.public_bytes(
                                                    encoding=serialization.Encoding.PEM,
                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                                ),
                            'nonce': sender_nonce,
                        })

            packet = base64.b64encode(
                        sym_encrypt(to_encrypt, clients[receiver].sym_key, clients[receiver].iv)
                    )

            response = construct_msg(
                'key establishment',
                4,
                {
                    'packet': packet,
                    'signature': base64.b64encode(sign(packet, PRIVATE_KEY))
                }
            )

            send_signed_message(response, True, clients[clients[sender].peer].sock)

        else:
            print 'key establishment fail'
            # response = construct_msg(
            #     'error',
            #     0,
            #     asym_encrypt(json.dumps({
            #         'message': 'Signature Verification Failed'
            #     }), public_key))
            # socket.send(response, client_ip)

#
# # Logout the client from the server
# def logout(order, content, source_ip):
#     if (order == 1):
#         nonce = content['nonce']
#         signed_username = sign(get_client_by_ip('username'), PRIVATE_KEY)
#         construct_msg(
#             'logout',
#             1,
#             json.dumps({
#                 'signature': signed_username,
#                 'nonce': nonce + 1
#             })
#         )
#     socket.send(response, source_ip)
#     client_username = get_client_by_ip(source_ip)['username']
#     # Filter out client pairs with client that just logged output
#     # Message other member to let them know logged out


def list_user(order, content, source_ip, sock):
    active_users = get_active_user()
    response = {
        'type': 'list',
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
            data, client_address = conn.recvfrom(2048)

            # Load client data as JSON
            client_packet = json.loads(data)['message']
            # Route the message based on type
            message_types[client_packet['type']](
                client_packet['order'],
                client_packet['content'],
                client_address, conn)

        except ValueError as e:
            for client in clients:
                if clients[client].sock == conn:
                    clients[client].active = False

                    print client + ' has disconnected'

            break

        except Exception as e:
            pass

    conn.close()


def main():
    # Get Server Config Info
    # with open('server.json') as server_config:
    #     server_config_data = json.loads(server_config)

    # Initialize Socket

    print "Server Initialized..."
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('localhost', 9090)
    sock.bind(server_address)

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.bind(('', PORT))

    tcp_sock.listen(10)

    with open('users.json') as user_config:
        users = json.load(user_config)
        for username in users:
            client = ClientInfo(users[username])
            clients[username] = client

    while 1:

        conn, addr = tcp_sock.accept()
        conn.setblocking(0)
        print 'Connected with ' + addr[0] + ':' + str(addr[1])

        start_new_thread(client_thread, (conn,))

    with open('users.json') as user_config:
        users = json.load(user_config)
        for username in users:
            client = ClientInfo(users[username])
            clients[username] = client

if __name__ == "__main__":
    main()
