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

connectedClients = []

print "Server Initialized..."

while True:




