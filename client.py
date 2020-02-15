"""
Created: Feb. 15, 2020
Updated:

Author: Suleyman
=== DETAILS ===
This file houses the client object responsible for establishing and passing data to the server
"""

#!/usr/bin/env python3

import socket

HOST = '127.0.0.1'
PORT = 8888

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skt:
        print(f'Client establishing connection to IP Address "{HOST}:{PORT}"')
        skt.connect((HOST, PORT))

        print('Client sending "Hello World"...')
        skt.sendall(b'Hello World')

        print(f'Client received: {repr(skt.recv(1024))}')
