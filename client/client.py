#! /usr/bin/env python

import argparse
import socket
import ssl
import sys

class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.check_hostname = True
        # Set CA location in order to check server certificates
        self.context.load_verify_locations('/home/rapha/projets/3dtrust/ca_cert/minissl-ca.pem')
        try:
            # Load is own certificate and the related key
            # An SSLError is raised if the client private key doesn't
            # match with the client certificate.
            self.context.load_cert_chain(
                    '/home/rapha/projets/3dtrust/client/minissl-client.pem',
                    '/home/rapha/projets/3dtrust/client/minissl-client.key.pem'
            )
        except ssl.SSLError, (value, message):
            print message
            sys.exit(value)

    def connec(self):
        conn = self.context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname = 'minissl-SERVER'
        )

        try:
            conn.connect((self.host, self.port))
        except ssl.SSLError, (value, message):
            print message
            print "Exiting"
            sys.exit(value)

        conn.send('GET filenam')
        data = conn.recv(1024)
        print 'data received : ' + data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description = 'TLS Client - Send a GET filename request',
            formatter_class = argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-hostname', default = '127.0.0.1', help = ' ')
    parser.add_argument('-port', default = 443, type = int, help = ' ')
    args = parser.parse_args()
    c = Client(args.hostname, args.port)
    c.connec()

