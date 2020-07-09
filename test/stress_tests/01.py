"""
This unit test creates 200 simultaneous connections to the server, kills them all in the same second,
and verifies that the server properly sends "LWT" - Last Will and Testament to all connections
"""

import socket
import unittest
from multiprocessing.pool import ThreadPool
from time import time, sleep
from random import randint

num_of_clients = 200
timeout_time = 30
kill_time = time() + 25


def toggle_tcp_connection():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('192.168.1.78', 8888))
    client.settimeout(timeout_time)
    sleep(kill_time - time() + randint(1, 100)/100)
    client.send('exit'.encode('utf-8'))
    end_time = time() + timeout_time
    while time() < end_time:
        try:
            output = client.recv(1024 * 4).decode('utf-8')
            if 'LWT' in output:
                sleep(1)
                client.close()
                return 'GOT LWT'
        except socket.timeout:
            client.close()
            return 'SOCKET TIMEOUT'
    client.close()
    return 'END TIME REACHED'


class Hundreds(unittest.TestCase):
    def setUp(self) -> None:
        print('Setup')
        self.pool = ThreadPool(processes=num_of_clients)
        self.total_success = 0

    def tearDown(self) -> None:
        print(f'Got {self.total_success}/{num_of_clients} successful closures')
        print('Teardown')
        self.pool.close()

    def test_something(self):
        print('Test Start')
        self.processes = list()
        for _ in range(num_of_clients):
            self.processes.append(self.pool.apply_async(toggle_tcp_connection))
            sleep(0.1)
        for _ in self.processes:
            _.wait(timeout=timeout_time)
            assert 'GOT LWT' in _.get()
            self.total_success += 1
        print('Test End')


if __name__ == '__main__':
    unittest.main()
