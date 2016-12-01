import socket
import threading
import select
import time
import sys
import argparse
import json
from module import *

parser = argparse.ArgumentParser()
parser.add_argument("-sip", help="server ip", default="localhost")
parser.add_argument("-sp", help="server port", type=int, default=9090)
args = parser.parse_args()
serverIp = args.sip
serverPort = args.sp

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(0)
keepAlive = True

class ServerListener(threading.Thread):
	def __init__(self, threadId, name, sock):
		threading.Thread.__init__(self)
		self.threadId = threadId
		self.name = name
		self.sock = sock

	def run(self):
		global keepAlive
		while keepAlive:
			time.sleep(1)
			try: 
				response = sock.recv(1024)
				decodedResponse = json.loads(response)
				msgToPrint = "<From {}:{}>: {}".format(decodedResponse['ip'], decodedResponse['port'], decodedResponse['content'])
				print msgToPrint
				sys.stdout.write("> ")
				sys.stdout.flush()
			except ValueError:
				# server sends somthing that cannot be decoded:
				print "invalid message from server: ", response
			except:
				# server doesn't send anything so ignore
				pass
			
class InputListener(threading.Thread):
	def __init__(self, threadId, name, sock):
		threading.Thread.__init__(self)
		self.threadId = threadId
		self.name = name
		self.sock = sock

	def run(self):
		greeting = GreetingPacket()
		sock.sendto(greeting.getRawMessage(), (serverIp, serverPort))
		global keepAlive
		while keepAlive:
			try: 
				message = raw_input("> ")
				messagePacket = MessagePacket(message)
				sock.sendto(messagePacket.getRawMessage(), (serverIp, serverPort))
			except (KeyboardInterrupt, SystemExit, EOFError):
				# kills all the thread when user hits ctrl+c
				keepAlive = False
				break
			except:
				break


serverListener = ServerListener(1, "server listener", sock)
inputListener = InputListener(2, "input listener", sock)

print "Write messages to send to broadcast server (CTRL-D to stop)"

try:
	inputListener.start()
	serverListener.start()
	inputListener.join()
	serverListener.join()
except:
	# in case of exception we will kill all thread
	keepAlive = False
	sys.exit()