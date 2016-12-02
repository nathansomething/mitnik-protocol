import socket
import sys
import argparse
import json
from module import *
from util import *

PUBLIC_KEY = ""
PRIVATE_KEY = ""

# {Username: username, Public Key: public key, IP: ip}
active_clients = []

# (client1, client2)
client_pairs = []

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

# Authenticate the user
def authenticate(username, password):


# Authenticate the user with the server
def authentication(order, content, source_ip):
    if (order == 1):
        # Read client packet
        content = asym_decrypt(content, PRIVATE_KEY)
        username = content['user']
        password = content['password']
        nonce = content['nonce']
        public_key = content['public_key']

        # Generate a new nonce
        nonce2 = gen_nonce()

        # Make sure the client has a valid username and password
        if authenticate(identity, password):
            # Update the active user log
            active_clients.append({
                'username': username,
                'ip': source_ip,
                'public_key': public_key
            })
            response = construct_msg(
                'authentication',
                1,
                asym_encrypt(
                    json.dumps({
                        'nonce1': nonce,
                        'nonce2': nonce2
                    }), public_key)
            )
        else:
            response = construct_msg(
                'error',
                0,
                asym_encrypt(json.dumps({
                    'message': 'Authentication Failed: Incorrect Username or Password'
                }))
            )
    elif (order == 2):
        signature = content['signature']
        if verify(signature, nonce2, public_key):
            response = construct_msg(
                'authentication',
                2,
                sign(nonce2 + 1, PRIVATE_KEY)
            )
        else:
            response = construct_msg(
                'error',
                0,
                json.dumps({
                    'message': 'Authentication Failed: Signature Verification Failed'
                })
            )
    socket.send(response, client_ip)

# Establish a shared key between two clients
def establishment(order, content, source_ip):
    requested_client_identity = ""
    if (order == 1):
        # Read Client Packet
        content = asym_decrypt(content, PRIVATE_KEY)
        requested_client_identity = content['requested_client']
        signature = content['signature']
        requested_public_key = get_client_by_username(requested_client_identity)['public_key']
        if requested_public_key:
            if verify(signature, requested_client_identity, public_key):
                response = construct_msg(
                    'establishment',
                    1,
                    asym_encrypt(json.dumps({
                        'requested_public_key': requested_public_key,
                        'nonce': get_nonce()
                    }), public_key)
                )
            else:
                response = construct_msg(
                    'error',
                    0,
                    requested_content = asym_encrypt(json.dumps({
                        'message': 'Signature Verification Failed'
                    }), public_key)
                )
        else:
            response = construct_msg(
                'error',
                0,
                requested_content = asym_encrypt(json.dumps({
                    'message': 'Public Key Not Found'
                }), public_key)
            )
        socket.send(response, client_ip)
    elif (order == 2):
        signatrue = content['signatrue']
        if verify(signatrue, nonce, public_key):
            response = construct_msg(
                'establishment',
                2,
                asym_encrypt(json.dumps({
                    'client_connection_request': identity,
                    'sender_public_key': public_key,
                    'nonce': nonce,
                    'signature': sign(get_client_by_username(requested_client_identity)['public_key'], PRIVATE_KEY)
                }))
            )
            socket.send(response, get_client_by_username(requested_client_identity)['ip'])
            client_pairs.append((get_client_by_ip(source_ip)['username'], requested_client_identity))
        else:
            response = construct_msg(
                'error',
                0,
                asym_encrypt(json.dumps({
                    'message': 'Signature Verification Failed'
                }), public_key))
            socket.send(response, client_ip)

# Logout the client from the server
def logout(order, content, source_ip):
    if (order == 1):
        nonce = content['nonce']
        signed_username = sign(get_client_by_ip('username'), PRIVATE_KEY)
        construct_msg(
            'logout',
            1,
            json.dumps({
                'signature': signed_username,
                'nonce': nonce + 1
            })
        )
    socket.send(response, source_ip)
    client_username = get_client_by_ip(source_ip)['username']
    # Filter out client pairs with client that just logged output
    # Message other member to let them know logged out


# Message type categories to send to
message_types = {
    "authentication": authentication,
    "establishment": establishment,
    "message": message,
    "logout": logout
}

def main():
    # Get Server Config Info
    server_config_data = {}
    with open('server.json') as server_config_file:
        server_config_data = json.loads(server_config)

    # Initialize Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverAddress = (server_config_data['IP'], server_config_data['Port'])
    sock.bind(serverAddress)

    print "Server Initialized..."
    while True:
        # Listen for messages from clients
    	data, client_ip = sock.recvfrom(1024)
    	try:
            # Load client data as JSON
    		client_packet = json.loads(data)
            # Route the message based on type
    		message_types[client_packet['type']](
                client_packet['order'],
                client_packet['content'],
                source_ip)

    	except Exception as ex:
    		print "exception raised: ", ex

if __name__ == "__main__":
    main()
