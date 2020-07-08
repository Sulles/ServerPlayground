"""
=============== SERVER SOCKET THREAD ===============
SocketThread runs a listener thread that constantly monitors the server's socket for new connections.
It is responsible for:
    - Starting/Stopping listening thread
    - Pausing/Resuming listening thread
    - Adding new connections to the call_back (here a Queue)
"""

import socket
from queue import Full

from src.lib.util import LogWorthy, kill_thread, lockable
from . import Thread, sleep
from .. import RLock


class SocketThread(LogWorthy):
    def __init__(self, log_file, call_back):
        """
        Initializer for SocketThread object
        :param log_file: string name of logging file
        :param call_back: call back function, here Queue.put_nowait
        """
        # General
        LogWorthy.__init__(self, log_file)
        self.name = 'SocketThread'
        self.lock = RLock()

        # IP constants
        self.ip_address = ''
        self.ip_port = 8888

        # TCP socket
        self.socket = None
        self.socket_timeout = 0.2
        self.socket_backlog = 2

        # Threading
        self.is_alive = False
        self.kill_thread = False
        self.call_back = call_back
        self.listener = None
        self.log('Initialization complete!')

    """ === PROCESS START/STOP === """

    def start(self):
        """ This method recreates and starts the thread """
        if self.socket is not None:
            self.log('Terminating existing Socket...')
            del self.socket

        self.log('Starting...')

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.ip_address, self.ip_port))
        self.log('Socket successfully bound')

        self.is_alive = True
        self.kill_thread = False
        self.listener = Thread(target=self.wait_for_next_connection, args=(self,))
        self.listener.start()
        self.log('Thread successfully started')
        return None

    def stop(self):
        """ This method will kill the thread """
        self.log('Stopping...')

        self.kill_thread = True
        kill_thread(self.log, self.listener)
        self.is_alive = False

        self.socket.close()
        self.log('Socket closed')
        return None

    @lockable
    def restart(self, data: dict = None):
        """ This method will kill then restart the listener thread """
        self.stop()
        self.start()
        if data is not None:
            data['response'] = f'{self.name} restarted'
            return data
        else:
            return None

    """ === PROCESS PAUSE/RESUME === """

    def pause(self):
        """ This method will pause the thread """
        self.log('Pausing listener thread')
        self.is_alive = False
        return None

    def resume(self):
        """ This method will resume the thread """
        self.log('Resuming listener thread')
        self.is_alive = True
        return None

    """ === THREADS === """

    @staticmethod
    def wait_for_next_connection(this):
        """ Threaded listener for new connection """
        while not this.kill_thread:  # kill switch for thread
            try:
                if this.is_alive:  # pause/resume switch for thread
                    # this.log('Waiting for next connection...')
                    try:
                        # Set socket variables
                        this.socket.settimeout(this.socket_timeout)
                        this.socket.listen(this.socket_backlog)
                        # Accept a new connection
                        (connection, (ip, port)) = this.socket.accept()
                        this.log('New connection found!')
                        # Add info to connection queue
                        this.call_back((connection, (ip, port)))
                    except socket.timeout:
                        # this.log('Socket timed out waiting for new connection!')
                        pass
                    except Full:
                        this.log('Connection is Queue is full! Waiting 1 sec to process all connections in queue...')
                        sleep(1)
                    except Exception as e:
                        this.log('Got error while waiting for next connection!')
                        raise e
                else:
                    this.log('Listener was paused')
                    sleep(1)
            except Exception as e:
                print('CRITICAL ERROR 0: Error found in threaded listener for new connections!')
                raise e

    """ === GETTERS === """

    def is_functional(self):
        if self.is_alive and not self.kill_thread and self.listener.is_alive():
            return True
        return False

    """ === MISC === """

    def log(self, log):
        self._log(f'[{self.name}] {log}')

    def debug(self, log):
        self._debug(f'[{self.name}] {log}')

    """ === CLEANUP ==== """

    def __del__(self):
        if self.is_alive:
            self.stop()
