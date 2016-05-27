#! /usr/bin/env python

import argparse
import os
import socket
import ssl
import sys

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # Set CA location in order to check client certificates
        self.context.load_verify_locations('/home/rapha/projets/3dtrust/ca_cert/minissl-ca.pem')
        # Require a certificate for each client
        self.context.verify_mode = ssl.CERT_REQUIRED
        # Register a callback function that will be called after
        # the TLS Client Hello handshake message has been received
        self.context.set_servername_callback(self.verify_callback)
        try:
            # Load is own certificate and the related key
            # An SSLError is raised if the server private key doesn't
            # match with his certificate.
            self.context.load_cert_chain(
                certfile = "/home/rapha/projets/3dtrust/server/minissl-server.pem",
                keyfile = "/home/rapha/projets/3dtrust/server/minissl-server.key.pem"
            )
        except ssl.SSLError, (value, message):
            print message
            sys.exit(value)
        #TODO context.set_ciphers

    def verify_callback(self, ssl_socket, server_name, context):
        print ssl_socket
        print server_name
        print context

    def deal_with_client(self, connstream):
        data = connstream.recv(1024)
        print "new client"
        print 'data received : ' + data
        # null data means the client is finished with us
        if data == 'GET filename':
            connstream.send("encrypted file")
        # finished with client

    def run(self):
        bindsocket = socket.socket()
        bindsocket.bind((self.host, self.port))
        bindsocket.listen(16)

        while True:
            newsocket, fromaddr = bindsocket.accept()
            try:
                connstream = self.context.wrap_socket(newsocket,
                                                      server_side = True)
            except ssl.SSLError, (value, message):
                print message
                print 'Connexion with client closed'
                continue

            try:
                self.deal_with_client(connstream)
            except ssl.SSLError, (value, message):
                print message
                print 'Error dealing with client'
            finally:
                print 'Connexion with client closed'
                connstream.shutdown(socket.SHUT_RDWR)
                connstream.close()

def def_path(path_file):
    path = os.path.dirname(sys.argv[0])
    if path == '':
        path = os.curdir
    return os.path.normpath(os.path.join(path, path_file))

if __name__ == "__main__":
    ca = def_path('../ca_cert/minissl-ca.pem')
    cert = def_path('minissl-server.pem')
    key = def_path('minissl-server.key.pem')

    parser = argparse.ArgumentParser(
            description = 'TLS Server - Respond on GET filename request',
            formatter_class = argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--hostname', default = '127.0.0.1', help = ' ')
    parser.add_argument('--port', default = 443, type = int, help = ' ')
    parser.add_argument('--ca', default = ca, help = ' ')
    parser.add_argument('--cert', default = cert, help = ' ')
    parser.add_argument('--key', default = key, help = ' ')
    args = parser.parse_args()
    s = Server(args.hostname, args.port)
    s.run()

