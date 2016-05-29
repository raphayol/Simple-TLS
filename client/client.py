#! /usr/bin/env python

import argparse
import hashlib
import hmac
import os
import socket
import ssl
import sys

BLOCK_SIZE = 1024

class Client:
    def __init__(self, host, port, ca, cert, key, stock, filename):
        self.host = host
        self.port = port
        self.stock = stock
        if not os.path.isdir(stock):
            print 'The stock directory %s doesn\'t exist. Exiting' %stock
            sys.exit(1)
        self.filename = filename
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # Require a certificate from server
        self.context.verify_mode = ssl.CERT_REQUIRED
        # Put this value to True if you use a known howtsname (not an ip)
        # and if you want to check that this hostname matchs the server
        # certificate
        self.context.check_hostname = False
        # Set CA location in order to check server certificates
        self.context.load_verify_locations(ca)
        try:
            # Load is own certificate and the related key
            # An SSLError is raised if the client private key doesn't
            # match with the client certificate.
            self.context.load_cert_chain(cert, key)
        except ssl.SSLError, (value, message):
            print message
            sys.exit(value)

    def get_file(self, ssl_socket):
        ssl_socket.send('GET ' + self.filename)
        # Receive secret use for HMAC from server
        secret = ssl_socket.recv(BLOCK_SIZE)
        if secret == 'NO':
            # If secret == 'NO' : the requested file doesn't exist
            print '%s doesn\'t exist on the server' %self.filename
            return
        file_path = self.stock + '/' + self.filename
        # Use oh SHA1 algorithm to hash file content
        digester = hmac.new(secret, '', hashlib.sha1)
        # Receive file content by block
        # compute HMAC signature to verify file content
        f = open(file_path, 'w+')
        while True:
            block = ssl_socket.recv(BLOCK_SIZE)
            if block == 'END':
                if not ssl_socket.recv(BLOCK_SIZE) == 'END':
                    ssl_socket.recv(BLOCK_SIZE)
                    f.write(block)
                    digester.update(block)
                break
            f.write(block)
            digester.update(block)
        f.close()
        # Receive HMAC signature for the requested file
        signature = ssl_socket.recv(BLOCK_SIZE)
        # Compare our signature with the one sent by server
        if signature == digester.hexdigest():
            # We got the good file content
            ssl_socket.send('OK')
            print 'File %s well received' %self.filename
        else:
            # Contents are different between client and server
            ssl_socket.send('KO')
            print 'Error : digest are not the same' %self.filename

    def deal_with_server(self):
        ssl_socket = self.context.wrap_socket(socket.socket(socket.AF_INET),
                                              server_hostname = self.host)
        try:
            # Try to connect to the server
            ssl_socket.connect((self.host, self.port))
            print 'connected to %s:%d' %(self.host, self.port)
            # Send a Get request in order to received the file
            self.get_file(ssl_socket)
        except ssl.SSLError, (value, message):
            print 'Error dealing with server :\r\n\t%s' %message
        finally:
            print 'Connexion with server closed'
            ssl_socket.shutdown(socket.SHUT_RDWR)
            ssl_socket.close()

def def_path(path_file):
    path = os.path.dirname(sys.argv[0])
    if path == '':
        path = os.curdir
    return os.path.normpath(os.path.join(path, path_file))

if __name__ == "__main__":
    ca = def_path('../ca_cert/minissl-ca.pem')
    cert = def_path('minissl-client.pem')
    key = def_path('minissl-client.key.pem')
    stock = def_path('stock')

    parser = argparse.ArgumentParser(
            description = 'TLS Client - Send a GET filename request',
            formatter_class = argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--hostname', default = '127.0.0.1', help = ' ')
    parser.add_argument('--port', default = 443, type = int, help = ' ')
    parser.add_argument('--ca', default = ca, help = ' ')
    parser.add_argument('--cert', default = cert, help = ' ')
    parser.add_argument('--key', default = key, help = ' ')
    parser.add_argument('--stock', default = stock, help = ' ')
    parser.add_argument('--filename', default = 'toto', help = ' ')
    args = parser.parse_args()
    c = Client(args.hostname, args.port, args.ca, args.cert,
               args.key, args.stock, args.filename)
    c.deal_with_server()
