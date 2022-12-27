#!/usr/bin/env python2

import socket
import SocketServer, SimpleHTTPServer

PORT = 8888

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("gmail.com", 80))
localIP = s.getsockname()[0]
s.close()

print "Starting server on " + localIP + ":" + str(PORT)

Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
server = SocketServer.TCPServer(('', PORT), Handler)
server.serve_forever()
