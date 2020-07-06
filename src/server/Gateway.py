"""
=============== GATEWAY ===============
Requires password to access gateway. Password cross-referenced by Gateway will be hashed version of string password
Command:
    status: Display the status of:
        Default shows all    (-server, -sockets, -conns)
        -server     (backend server status)
        -sockets    (all socket statuses)
        -conns      (all connection statuses)
    start: Start the server
    kill: Kill the server
    restart: Kill then start the server
"""

from queue import Empty

from src.lib.util import *
from . import time
from .Server import Server
from .SocketThread import SocketThread
from .. import Queue, SECURE_SERVICE, INSECURE_SERVICE, RLock


class Gateway(LogWorthy):
    """
    =============== COMMUNICATIONS GATEWAY ===============
    Gateway object is the gateway between the socket connection and all other Server-side components
    Gateway is responsible for:
        - Creating socket connection point to server IP address
        - Sending all new socket connections to Server for handling
        - Master clean-up organizer, all components should be able to be cleaned up through gateway cleanup
    TODO: Make a global queue watcher that removes unhandled data from the queue
    """

    def __init__(self, log_file=None):
        """
        Initializer for Gateway interface. Is responsible for:
            - Establishing socket connection to ip address
            - Starting connection_thread which will add new connections to the connection_queue as they appear
            - Starting the backend data processing object
        """
        # General
        LogWorthy.__init__(self, log_file)
        self.name = 'Gateway'
        self.is_running = True
        self.connection_backlog_size = 5
        self.socket_timeout = 0.1
        self.lock = RLock()

        # IP constants
        self.ip_address = ''
        self.ip_port = 8888

        # Threading
        self.connection_queue = Queue(self.connection_backlog_size)
        self.socket_thread = SocketThread(log_file, self.connection_queue.put_nowait)
        self.log('Socket initialized')

        # Server
        self.server = Server()
        self.log('Server initialized')

        # CLI connection
        self.cli_connection = None
        # Secure Service
        SECURE_SERVICE.register_service('gateway_stop_listener', self.stop_socket_thread)
        SECURE_SERVICE.register_service('gateway_start_listener', self.start_socket_thread)
        SECURE_SERVICE.register_service('gateway_restart_listener', self.socket_thread.restart)
        SECURE_SERVICE.register_service('gateway_status', self.get_status)
        SECURE_SERVICE.register_service('server_status', self.get_server_status)
        SECURE_SERVICE.register_service('server_kill_connection', self.server.kill_connection)
        SECURE_SERVICE.register_service('server_kill_all_connections', self.server.kill_all_connections)
        SECURE_SERVICE.register_service('server_kill_all_connections_except_me',
                                        self.server.kill_all_connections_except_me)
        SECURE_SERVICE.register_service('server_kill_watchdog', self.server.kill_watchdog_thread)
        SECURE_SERVICE.register_service('server_start_watchdog', self.server.start_watchdog)
        SECURE_SERVICE.register_service('server_restart_watchdog', self.server.restart_watchdog_thread)
        SECURE_SERVICE.register_service('num_of_connections', self.server.get_num_connections)
        # Insecure Service
        INSECURE_SERVICE.register_service('num_of_connections', self.server.get_num_connections)

    """ === LISTENER START/STOP === """

    @lockable
    def start_socket_thread(self, data: dict = None):
        self.socket_thread.start()
        if data is not None:
            data['response'] = 'Started socket thread'
            return data

    @lockable
    def stop_socket_thread(self, data: dict = None):
        self.socket_thread.stop()
        if data is not None:
            data['response'] = 'Stopped socket thread'
            return data

    """ === MAIN === """

    def main(self, timeout=None):
        """
        Main runner method of the Gateway, is responsible for:
            - Monitoring connection_queue for new connections and triaging them to CLI or Server
            - Monitoring response_callback for new responses to send
            - Handling CLI data requests
        """
        end_time = -1
        infinite = False
        if timeout is not None:
            self.log(f'Starting timed main loop for {timeout} seconds')
            end_time = time() + timeout
        else:
            self.log('Starting infinite main loop!')
            infinite = True

        while time() < end_time or infinite:
            # Try and get a new connection
            try:
                (connection, (ip, port)) = self.connection_queue.get(timeout=600)
                if self.server.get_num_connections() < 10:
                    self.log(f'Got new connection at {ip}:{port}')
                    self.server.handle_new_connection(connection, ip, port)
                else:
                    connection.close()
                    self.log(f'SERVER FULL: New connection at {ip}:{port} could not be established and was closed')
            except Empty:
                pass
            except Exception as e:
                self.log('CRITICAL ERROR 1: Failed to get new connection from connection_queue!')
                self.log(e)
                raise e

            # self.log('Sleeping for a hot second')
            self.log('.')

    """ === GETTERS === """

    @lockable
    def get_status(self, data: dict = None):
        status = f'===== GATEWAY STATUS =====\n' \
                 f'Listener Thread is {"alive" if self.socket_thread.is_functional() else "dead!"}\n' \
                 f'{self.server.get_num_connections()} Active Client Connections'
        if data is not None:
            data['response'] = status
            return data
        else:
            return status

    @lockable
    def get_server_status(self, data: dict = None):
        status = self.server.get_status()
        if data is not None:
            data['response'] = status
            return data
        else:
            return status

    """ === SETTERS === """

    """ === MISC === """

    def log(self, log):
        self._log(f'[{self.name}] {log}')

    def debug(self, log):
        self._debug(f'[{self.name}] {log}')

    """ === CLEANUP === """

    def cleanup(self):
        """
        Clean-up method will:
            - Gracefully close connection_thread
            - Remove all queued tasks in connection_queue
            - Wait for return on clean-up call for all active connection processes
            - Verify connection_thread is closed and connection_queue is empty
        """
        self.log('Cleanup Beginning')
        self.stop_socket_thread()
        self.server.cleanup()
        self.log('Cleanup End')
