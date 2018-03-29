from client_interface import TORPathingServer
from Crypto.PublicKey import RSA
import sys


def test():
    key = RSA.generate(2048)

    server = TORPathingServer(sys.argv[1], int(sys.argv[2]))
    server.register(2100, key.publickey())
    route = server.get_route()

    print route[0][2] == key.publickey()
    print route
    server.unregister()
    print server.get_route()


if __name__ == '__main__':
    test()
