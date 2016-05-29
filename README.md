# Simple TLS file transfert

This repository present two scripts written in python : a server and a client.
The client can request file present on the server and received it over a
secured channel.

#### Server Options
    usage: server.py [-h] [--hostname HOSTNAME] [--port PORT] [--ca CA]
                     [--cert CERT] [--key KEY] [--store STORE]

    TLS Server - Respond on GET filename request

    optional arguments:
      -h, --help           show this help message and exit
      --hostname HOSTNAME
      --port PORT
      --ca CA              certification authority certificate
      --cert CERT          server certificate
      --key KEY            server private key
      --store STORE        directory where files are stored

#### Client Options
    usage: client.py [-h] [--hostname HOSTNAME] [--port PORT] [--ca CA]
                     [--cert CERT] [--key KEY] [--stock STOCK]
                     [--filename FILENAME]

    TLS Client - Send a GET filename request

    optional arguments:
      -h, --help           show this help message and exit
      --hostname HOSTNAME
      --port PORT
      --ca CA              certification authority certificate
      --cert CERT          client certificate
      --key KEY            client private key
      --stock STOCK        directory where files are stored after reception
      --filename FILENAME

#### Possible improvements :
*  Add more cypher suites
*  Non-blocking sockets

#### Usefull documentation :
* [Socket with python](https://docs.python.org/2.7/howto/sockets.html)
* [SSL/TLS with python](https://docs.python.org/2/library/ssl.html)
* [RFC2104 for HMAC](https://tools.ietf.org/html/rfc2104.html)

