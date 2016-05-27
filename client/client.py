#! /usr/bin/env python

import socket, ssl, sys

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
            conn.connect(("192.168.1.13", 443))
        except ssl.SSLError, (value, message):
            print message
            print "Exiting"
            sys.exit(value)

        conn.send('AaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaGET filename')
        cert = conn.getpeercert()
        print cert

if __name__ == "__main__":
    c = Client('192.168.1.13', 443)
    c.connec()

