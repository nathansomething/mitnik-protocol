import socket
import sys
import argparse
import json
from module import *

parser = argparse.ArgumentParser()
parser.add_argument("-sp", help="server port", type=int, default=9090)
args = parser.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverAddress = ('localhost', args.sp)
sock.bind(serverAddress)

class InvalidPacketException(Exception):
    def __init__(self, message):
        self.message = message

connectedClients = []
print "Server Initialized..."
while True:
    data, senderAddress = sock.recvfrom(1024)
    try:
        decodedData = json.loads(data)
        packetType = decodedData['type']
        if packetType == 'GREETING':
            if senderAddress not in connectedClients:
                print "registered {} to this server".format(senderAddress)
                connectedClients.append(senderAddress)

        elif packetType == 'MESSAGE':
            if senderAddress not in connectedClients:
                raise InvalidPacketException("User from {} has not registered yet".format(senderAddress))
            else:
                for clientAddress in connectedClients:
                    sendPacket = IncomingPacket(senderAddress[0], senderAddress[1], decodedData['content'])
                    sock.sendto(sendPacket.getRawMessage(), clientAddress)

        else:
            raise InvalidPacketException("Invalid packet type from {}".format(clientAddress))

    except InvalidPacketException as err:
        print err.message
    except Exception as ex:
        print "exception raised: ", ex



