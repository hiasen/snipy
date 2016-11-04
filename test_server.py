#!/usr/bin/env python3
import socketserver
import sys

from sniparse import get_sni


class EchoSNIHandler(socketserver.BaseRequestHandler):
    def handle(self):
        host, port = self.client_address
        print("Got connection from {}:{}".format(host, port))
        data = self.request.recv(1024)
        hostname = get_sni(data)
        print("Server Name Indication: {}".format(hostname))


def run_server(host, port):
    print('Listening for tls connections on {}:{}'.format(host, port))
    server = socketserver.TCPServer((host, port), EchoSNIHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        host, port = sys.argv[1], int(sys.argv[2])
    else:
        host, port = "0.0.0.0", 9999
    run_server(host, port)
