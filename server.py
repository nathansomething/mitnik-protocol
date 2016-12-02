import socket
from util import *
import base64

PUBLIC_KEY = get_public_key('server_public_key.der')
PRIVATE_KEY = get_private_key('server_private_key.der')

# {Username: username, Public Key: public key, IP: ip}
active_clients = {}
clients = {}

# (client1, client2)
client_pairs = []


###############################################################################
## Client info
###############################################################################

class ClientInfo:

    def __init__(self, password):
        self.password = password
        self.ip = ''
        self.port = ''
        self.authentication_nonce = None
        self.active = False
        self.public_key = ''

    def pair_with(self, peer):
        self.peer = peer

    def login(self):
        self.active = True

    def isActive(self):
        return self.isActive()


# Retrieves a client by username
def get_client_by_username(username):
    for client in active_clients:
        if client['username'] == username:
            return client


# Retrieves a client by ip
def get_client_by_ip(ip):
    for client in active_clients:
        if client['ip'] == ip:
            return client


def authenticate(username, password):
    if username in clients:
        print clients[username].password
        return password == clients[username].password
    else:
        return False


def update_user(username, source_ip, public_key, nonce):
    client = clients[username]
    client.source_ip = source_ip
    client.public_key = public_key
    client.authentication_nonce = str(nonce)


def send_error_message(sock, addr):
    nonce = str(gen_nonce())
    error_message = {
        'type': 'error',
        'message': nonce,
        'signature': base64.b64encode(sign(nonce, PRIVATE_KEY))
    }

    sock.sendto(json.dumps(error_message), addr)


# Authenticate the user with the server
def authentication(order, content, client_address, sock):
    if order == 1:
        # Read client packet

        decoded_content = asym_decrypt(base64.b64decode(content), PRIVATE_KEY)
        content = json.loads(decoded_content)
        username = content['user']
        password = content['password']
        nonce = content['nonce']
        public_key = content['publicKey']

        # Generate a new nonce
        nonce2 = gen_nonce()

        # Make sure the client has a valid username and password
        if authenticate(username, password):
            # Update the active user log
            pub_key = load_public_key(str(public_key))

            update_user(username, client_address, pub_key, nonce2)
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

            print response
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
                2,
                base64.b64encode(sign(str(float(nonce) + 1), PRIVATE_KEY))
            )
        else:
            send_error_message(sock, client_address)

    sock.sendto(response, client_address)


# # Establish a shared key between two clients
# def establishment(order, content, source_ip):
#     requested_client_identity = ""
#     if order == 1:
#         # Read Client Packet
#         content = asym_decrypt(content, PRIVATE_KEY)
#         requested_client_identity = content['requested_client']
#         signature = content['signature']
#         requested_public_key = get_client_by_username(requested_client_identity)['public_key']
#         if requested_public_key:
#             if verify(signature, requested_client_identity, public_key):
#                 response = construct_msg(
#                     'establishment',
#                     1,
#                     asym_encrypt(json.dumps({
#                         'requested_public_key': requested_public_key,
#                         'nonce': get_nonce()
#                     }), public_key)
#                 )
#             else:
#                 response = construct_msg(
#                     'error',
#                     0,
#                     requested_content = asym_encrypt(json.dumps({
#                         'message': 'Signature Verification Failed'
#                     }), public_key)
#                 )
#         else:
#             response = construct_msg(
#                 'error',
#                 0,
#                 requested_content = asym_encrypt(json.dumps({
#                     'message': 'Public Key Not Found'
#                 }), public_key)
#             )
#         socket.send(response, client_ip)
#     elif order == 2:
#         signatrue = content['signatrue']
#         if verify(signatrue, nonce, public_key):
#             response = construct_msg(
#                 'establishment',
#                 2,
#                 asym_encrypt(json.dumps({
#                     'client_connection_request': identity,
#                     'sender_public_key': public_key,
#                     'nonce': nonce,
#                     'signature': sign(get_client_by_username(requested_client_identity)['public_key'], PRIVATE_KEY)
#                 }))
#             )
#             socket.send(response, get_client_by_username(requested_client_identity)['ip'])
#             client_pairs.append((get_client_by_ip(source_ip)['username'], requested_client_identity))
#         else:
#             response = construct_msg(
#                 'error',
#                 0,
#                 asym_encrypt(json.dumps({
#                     'message': 'Signature Verification Failed'
#                 }), public_key))
#             socket.send(response, client_ip)
#
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


def message():
    pass

# Message type categories to send to
message_types = {
    "authentication": authentication
    # "establishment": establishment,
    # "message": message,
    # "logout": logout
}


def main():
    # Get Server Config Info
    # with open('server.json') as server_config:
    #     server_config_data = json.loads(server_config)

    # Initialize Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('localhost', 9090)
    sock.bind(server_address)

    with open('users.json') as user_config:
        users = json.load(user_config)
        for username in users:
            client = ClientInfo(users[username])
            clients[username] = client

    print "Server Initialized..."
    while True:
        # Listen for messages from clients
        data, client_address = sock.recvfrom(1024)
        try:
            # Load client data as JSON
            client_packet = json.loads(data)
            # Route the message based on type
            message_types[client_packet['type']](
                client_packet['order'],
                client_packet['content'],
                client_address, sock)

        except Exception as ex:
            print "exception raised: ", ex

if __name__ == "__main__":
    main()
