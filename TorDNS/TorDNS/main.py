from SocketServer import ThreadingMixIn, TCPServer, BaseRequestHandler
from Crypt import Crypt
import logging
import argparse
from Crypto.PublicKey import RSA
import struct
import socket


dns_logger = logging.getLogger("TorDNS")
dns_logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
dns_logger.addHandler(ch)


class CustomTCPServer(ThreadingMixIn, TCPServer, object):
    def __init__(self, server_address, prikey, request_handler):
        super(CustomTCPServer, self).__init__(server_address, request_handler)
        self.prikey = prikey


class MyTCPHandler(BaseRequestHandler):
    REQ_LEN = 768

    def setup(self):
        pass

    def _pull(self, sock, length):
        message = ''
        while len(message) < length:
            message += sock.recv(length - len(message))
        return message

    def handle(self):
        dns_logger.info('handling connection from %s:%s' % self.client_address)

        dns_logger.debug("Waiting for request...")
        request = self._pull(self.request, self.REQ_LEN)
        dns_logger.debug("Pulled request")

        crypt = Crypt(private_key=self.server.prikey)
        hsh, request = crypt.decrypt(request)
        salt, request = request[:16], request[16:]
        ip, port, pubkey = struct.unpack(">4sL%ds" % crypt.PUB_DER_LEN, request)

        pubkey = RSA.importKey(pubkey)
        ip = socket.inet_ntoa(ip)

        crypt.setPublicKey(pubkey)
        crypt.auth(request, hsh)







        try:
            method, circ = self.server.cdb.get(header, self.server.crypt)
        except BadMethod:
            e = sys.exc_info()
            raise e[0], e[1], e[2]

        if method == self.server.cdb.ESTB:
            dns_logger.info("Building circuit")
            circ.build_circuit(self.request)
            self.server.cdb.add(circ)
        else:
            dns_logger.info("Handling request")
            status = circ.handle_connection(self.request)

            if status == circ.EXIT:
                dns_logger.info("Removing circuit %s" % repr(circ.name))
                self.server.cdb.remove(circ)
            else:
                dns_logger.info("Sucessfully returned request")

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", help="Port to bind DNS server to")
    parser.add_argument("prikey", help="Path to private key")
    args = parser.parse_args()
    return args.port, args.prikey


if __name__ == "__main__":
    port, prikey = parse_args()
    # Create the server, binding to localhost on PORT
    with open(prikey, "r") as f:
        prikey = f.read()
        prikey = RSA.importKey(prikey)


    dns_logger.info("Building server..")
    server = CustomTCPServer(("0.0.0.0", port), prikey, MyTCPHandler)

    dns_logger.info("Starting server...")
    server.serve_forever()
