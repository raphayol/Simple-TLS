#! /usr/bin/env python

import argparse
import hashlib
import hmac
import os
import socket
import ssl
import sys

def digest_file(filename, secret):
    # Use oh SHA1 algorithm to hash file content
    digester = hmac.new(secret, '', hashlib.sha1)
    f = open(filename, 'rb')
    try:
        while True:
            block = f.read(1024)
            if not block:
                break
            digester.update(block)
    finally:
        f.close()
    return digester.hexdigest()

class Server:
    def __init__(self, host, port, ca, cert, key, store):
        self.host = host
        self.port = port
        self.store = store
        if not os.path.isdir(store):
            print "The store directory %s doesn't exist. Exiting" %store
            sys.exit(1)

        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # Set CA location in order to check client certificates
        self.context.load_verify_locations(ca)
        # Require a certificate for each client
        self.context.verify_mode = ssl.CERT_REQUIRED
        # Register a callback function that will be called after
        # the TLS Client Hello handshake message has been received
        self.context.set_servername_callback(self.verify_callback)
        try:
            # Load is own certificate and the related key
            # An SSLError is raised if the server private key doesn't
            # match with his certificate.
            self.context.load_cert_chain(cert, key)
        except ssl.SSLError, (value, message):
            print message
            sys.exit(value)
        self.context.set_ciphers('AES128')

    def verify_callback(self, ssl_socket, server_name, context):
        print "New client HELLO received"

    def send_file(self, ssl_socket, filename):
        print 'GET %s request received' %filename
        # TODO verify filename (alphanumeric and present on server)
        # We can admit here that the requested file is already encrypted
        file_path = self.store + '/' + filename
        if not os.path.isfile(file_path):
            # The requested file is not found on the server
            # TODO Send error message to client
            print 'File doesn\'t exist'
            return
        # Generate random bytes secret used for HMAC
        secret = os.urandom(64)
        # Send secret to client
        ssl_socket.send(secret)
        # Send HMAC signature for this file
        ssl_socket.send(digest_file(file_path, secret));
        print digest_file(file_path, secret);

    def deal_with_client(self, ssl_socket):
        request = ssl_socket.recv(1024).split()
        # Treate all differents request here
        # For this example only GET "filename" request are handle
        if request[0] == 'GET':
            self.send_file(ssl_socket, request[1])
        # Null data means the client is finished with us
        # We have finished with this client now

    def run(self):
        bindsocket = socket.socket()
        bindsocket.bind((self.host, self.port))
        bindsocket.listen(16)

        while True:
            # Waiting for clients here
            newsocket, fromaddr = bindsocket.accept()
            try:
                # When a client is connected : begin a tls session
                ssl_socket = self.context.wrap_socket(newsocket,
                                                      server_side = True)
            except ssl.SSLError, (value, message):
                print message
                print 'Connexion with client closed'
                continue

            try:
                # When the TLS handshake has been done : listen client request
                self.deal_with_client(ssl_socket)
            except ssl.SSLError, (value, message):
                print "Error dealing with client :\r\n\t" + message
            finally:
                print 'Connexion with client closed'
                ssl_socket.shutdown(socket.SHUT_RDWR)
                ssl_socket.close()

def def_path(path_file):
    path = os.path.dirname(sys.argv[0])
    if path == '':
        path = os.curdir
    return os.path.normpath(os.path.join(path, path_file))

if __name__ == "__main__":
    ca = def_path('../ca_cert/minissl-ca.pem')
    cert = def_path('minissl-server.pem')
    key = def_path('minissl-server.key.pem')
    store = def_path('store')

    parser = argparse.ArgumentParser(
            description = 'TLS Server - Respond on GET filename request',
            formatter_class = argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--hostname', default = '127.0.0.1', help = ' ')
    parser.add_argument('--port', default = 443, type = int, help = ' ')
    parser.add_argument('--ca', default = ca, help = ' ')
    parser.add_argument('--cert', default = cert, help = ' ')
    parser.add_argument('--key', default = key, help = ' ')
    parser.add_argument('--store', default = store, help = ' ')
    args = parser.parse_args()
    s = Server(args.hostname, args.port, args.ca,
               args.cert, args.key, args.store)
    s.run()

