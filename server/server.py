#! /usr/bin/env python

import argparse
import hashlib
import hmac
import os
import socket
import ssl
import sys
import threading

BLOCK_SIZE = 1024
NB_MAX_CLIENT = 16
CIPHERS = 'AES128'

class Server:
    def __init__(self, host, port, ca, cert, key, store):
        self.host = host
        self.port = port
        self.store = store
        if not os.path.isdir(store):
            print 'The store directory %s doesn\'t exist. Exiting' %store
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
        self.context.set_ciphers(CIPHERS)

    def verify_callback(self, ssl_socket, server_name, context):
        print 'New client HELLO received'

    def send_file(self, ssl_socket, filename):
        print 'GET %s request received' %filename
        # TODO verify filename (alphanumeric and present on server)
        # We can admit here that the requested file is already encrypted
        file_path = self.store + '/' + filename
        # For security purpose filename must be alpha-nunmeric
        if (not os.path.isfile(file_path) or not filename.isalnum()):
            # The requested file is not found on the server
            print 'File doesn\'t exist'
            ssl_socket.send('NO')
            return
        # Generate random bytes secret used for HMAC
        secret = os.urandom(20)
        # Send secret to client
        ssl_socket.send(secret)
        # Use oh SHA1 algorithm to hash file content
        digester = hmac.new(secret, '', hashlib.sha1)
        # Send file content by block
        # compute HMAC for this file
        f = open(file_path, 'rb')
        while True:
            block = f.read(BLOCK_SIZE)
            if not block:
                break
            ssl_socket.send(block)
            digester.update(block)
        f.close()

        # Send end of file signal
        ssl_socket.send('END')
        ssl_socket.send('END')

        # Send HMAC signature for this file
        ssl_socket.send(digester.hexdigest())
        client_report = ssl_socket.recv(BLOCK_SIZE)
        if client_report == 'OK':
            print 'File %s well received by client' %filename
        else:
            print 'File %s not received by client' %filename

    def deal_with_client(self, ssl_socket):
        try:
            # When the TLS handshake has been done : listen client request
            request = ssl_socket.recv(BLOCK_SIZE).split()
            if request == []:
                # Null data means the client is finished with us
                return
            # Treate all differents request here
            # For this example only GET "filename" request are handle
            if request[0] == 'GET':
                self.send_file(ssl_socket, request[1])
            # We have finished with this client now
            ssl_socket.shutdown(socket.SHUT_RDWR)
        except ssl.SSLError, (value, message):
            print 'Error dealing with client :\r\n\t%s' %message
        except socket.error, (value, message):
            print 'Error dealing with client :\r\n\t%s' %message
        except:
            print 'Unknow error dealing with client'
        print 'Connexion with client closed'
        ssl_socket.close()

    def run(self):
        bindsocket = socket.socket()
        bindsocket.bind((self.host, self.port))
        bindsocket.listen(NB_MAX_CLIENT)
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
            # Treate client in a new thread
            t = threading.Thread(target=self.deal_with_client,
                                 args=([ssl_socket]))
            t.start()

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

