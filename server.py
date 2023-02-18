#!/usr/bin/env python3

import socket
import http.server, socketserver

PORT = 1485

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("gmail.com", 80))
localIP = s.getsockname()[0]
s.close()

print("Starting server on " + localIP + ":" + str(PORT))

Handler = http.server.SimpleHTTPRequestHandler
server = socketserver.TCPServer(('', PORT), Handler)
server.serve_forever()

#I turned it to Python3
