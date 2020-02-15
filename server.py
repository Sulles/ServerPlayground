"""
Created: Feb. 15, 2020
Updated:

Author: Suleyman

=== DETAILS ===
This file houses the server object responsible for collecting data from, and responding to, clients
"""

#!/usr/bin/env python3

import socket
from multiprocessing import process, Pool, cpu_count, Queue


HOST = '127.0.0.1'
PORT = 8888


class SuperSocket:
    def __init__(self):
        """ Initializer for SuperSocket class """
        super(SuperSocket, self).__init__()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('SuperSocket successfully initialized!')

    def clean_up(self):
        try:
            self.socket.close()
            print('Terminated SuperSocket')
        except Exception as e:
            print(f'Got error on SuperSocket cleanup!:\n{e}')
            raise e
        print('SuperSocket cleaned up')

class Server:
    def __init__(self):
        """ Initializer for main Server class """
        # Initialize connection params
        self.ip_address = '127.0.0.1'
        self.ip_port = 8888
        # Initialize socket objects
        socket_count = cpu_count() - 1 if cpu_count() > 2 else 2
        print(f'Server is creating {socket_count} sockets')
        self.socket_pool = Pool(socket_count)
        self.all_sockets = [SuperSocket() for _ in range(socket_count)]

        print('Socket Server object successfully initialized!')

    def clean_up(self):
        print('Server cleaning up all sockets...')
        for socket in self.all_sockets:
            socket.clean_up()


# class DemoServer:
#     def __init__(self):
#


if __name__ == "__main__":
    # server = Server()
    # server.clean_up()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skt:
        print(f'Server is binding socket to IP Address "{HOST}:{PORT}"')
        skt.bind((HOST, PORT))

        print('Server is now listening')
        skt.listen()

        print('Server is waiting for a socket connection...')
        conn, addr = skt.accept()

        with conn:
            print(f'Server successfully connected to {addr}!')
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print(f'Server received data: {repr(data)}, echoing back to client...')
                conn.sendall(data)
