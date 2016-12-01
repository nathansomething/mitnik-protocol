import json

class Packet(object):
	def __init__(self, packetType):
		self.type = packetType
		self.payload = {}
		self.payload['type'] = self.type
	def getRawMessage(self):
		return json.dumps(self.payload)

class GreetingPacket(Packet):
	def __init__(self):
		super(GreetingPacket, self).__init__("GREETING")

class IncomingPacket(Packet):
	def __init__(self, ip, port, content):
		super(IncomingPacket, self).__init__("INCOMING")
		self.ip = ip
		self.port = port
		self.content = content

		self.payload['ip'] = ip
		self.payload['port'] = port
		self.payload['content'] = content

class MessagePacket(Packet):
	def __init__(self, content):
		super(MessagePacket, self).__init__("MESSAGE")
		self.content = content
		self.payload['content'] = content
