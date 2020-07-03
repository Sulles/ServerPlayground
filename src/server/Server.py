"""
Created: Feb. 15, 2020
Updated: Feb. 18, 2020

Author: Suleyman

=== DETAILS ===
This file houses the following objects:
    - Gateway: Maintains an open connection for clients to connect to the server
    - Server: Maintains and monitors ClientConnections, responsible for authorization
    - Client Connection: Handles processing data received from the client
"""

import binascii
import hashlib
from queue import Empty
from threading import Thread
from time import sleep
from multiprocessing import RLock

from src.lib.util import *
from .. import INSECURE_SERVICE
from . import INSECURE_GET_NEXT_REQUEST, INSECURE_MAKE_REQUEST, INSECURE_SEND_RESPONSE
from .ClientConnection import ClientConnection

# ==================
# TESTING PLAYGROUND
hello = b'hello'
ihello = int.from_bytes(hello, byteorder='big')
bhello = bytes(ihello.to_bytes(length=len('hello'), byteorder='big'))


# ==================


class Server(LogWorthy):
    """
    =============== SERVER ===============
    The Server will handle all data processing and storing. It is responsible for:
        - Starting/Stopping a listener thread for each client connection
        - Processing all data received from clients
        - Adding data to an SQL database
        - Using a call_back (response_queue) to send response data to the client
    """

    def __init__(self, log_file=None):
        """ Initializer for Server object """
        #  General
        self.name = 'Server'
        self.log_file = log_file
        LogWorthy.__init__(self, log_file)

        # Security - Admin password
        self.admin_password = None
        with open('.pwd', 'r') as pwd_file:
            try:
                self.admin_password = pwd_file.readline()
            except Exception as e:
                self.log(f'CRITICAL ERROR -1: Could not read admin password!\n{e}')

        # Security - Session RSA keys

        # SQL
        self.sql = None

        # Connections + threading
        self.all_client_connections = list()
        self.request_lock = RLock()

        # Client Connection watcher thread
        self.panic_queue = Queue()
        self.kill_watchdog = False
        self.watchdog_is_alive = True
        self.watchdog_refresh = 0.1  # frequency that watchdog checks on it's threads
        self.watchdog_sleep = 1  # frequency that watchdog checks if it should be running
        self.connection_watcher = None
        self.start_watchdog()

        # Client Connection Insecure Requests thread
        self.kill_request = False
        self.request_is_alive = True
        self.request_refresh = 0.5  # frequency that request handler checks if a new insecure request exists
        self.request_sleep = 1  # frequency that request handler checks if it should be running
        INSECURE_SERVICE.register_service('verify_admin_pwd', self.verify_admin_password)
        INSECURE_SERVICE.register_service('auth_challenge', self.handle_auth_challenge)
        # self.insecure_request_lookup = dict(
        #     verify_admin_pwd=self.verify_admin_password,
        #     auth_challenge=self.handle_auth_challenge
        # )
        self.request_handler = None
        self.start_request_handler()

    """ === THREADS === """

    @staticmethod
    def watch_thread(this, get_next_panic):
        """
        Watchdog thread that Server uses to monitor all client connection panics
        :param this: Server self
        :param get_next_panic: Reference to Server panic_queue.get_nowait that is populated by ClientConnection
            threads when they panic and need to be closed.
        """
        this.log('Starting client connection watchdog')
        while not this.kill_watchdog:
            if this.watchdog_is_alive:
                try:
                    kill_name = get_next_panic()
                    kill_id = None
                    this.log('Got kill request!')
                    for conn in this.all_client_connections:
                        if conn.name == kill_name:
                            kill_id = this.all_client_connections.index(conn)
                            conn.stop()
                            this.log(f'Successfully killed {conn.name}!')
                    if kill_id is not None:
                        this.all_client_connections.pop(kill_id)
                        this.log(f'Removed {kill_name} from all client connections')
                except Empty:
                    pass
                except AttributeError as e:
                    this.log(f'Got error: {e}')
                    pass
                # this.log('Got nothing, so sleeping')
                sleep(this.watchdog_refresh)
            else:
                this.log('Not running watchdog, sleeping')
                sleep(this.watchdog_sleep)
        this.log('Client connection watchdog is ending!')

    @staticmethod
    def request_thread(this):
        """
        Request thread monitors insecure and secure global request threads for new requests
        :param this: Server self
        """
        while not this.kill_request:
            if this.request_is_alive:
                # try:
                #     request = SECURE_GET_NEXT_REQUEST()
                #     this.handle_secure_request(request)
                # except Empty:
                #     pass

                backlog_requests = list()

                try:
                    request = INSECURE_GET_NEXT_REQUEST()
                    this.log(f'Got insecure request: {request}')
                    if type(request) is dict and request['command'] in this.insecure_request_lookup.keys():
                        this.log(f'Got insecure request: {request}')
                        this.handle_insecure_request(this, request)
                    else:
                        # If we don't care about the request, add it to backlog
                        backlog_requests.append(request)
                except Empty:
                    for backlog in backlog_requests:
                        INSECURE_MAKE_REQUEST(backlog)
                    # this.log('No valid insecure request received, sleeping')
                    sleep(1.1)

    """ === THREADED HANDLERS ==="""

    @staticmethod
    def handle_insecure_request(this, request):
        this.log('Processing insecure request')
        try:
            if 'args' in request.keys():
                response = this.insecure_request_lookup[request['command']](request['args'])
            else:
                response = this.insecure_request_lookup[request['command']]()
            INSECURE_SEND_RESPONSE(dict(response=response, id=request['id']))
        except TypeError:
            this.log('Failed to execute ')

    """ === REQUEST METHODS === """

    def verify_admin_password(self, args):
        """ Verify that the provided password is an admin password """
        with self.request_lock:
            self.log('Verifying password provided matches admin password...')
            provided_password = args[0]
            salt = self.admin_password[:64]
            stored_password = self.admin_password[64:]
            pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'), 100000)
            pwdhash = binascii.hexlify(pwdhash).decode('ascii')
            success = pwdhash == stored_password
            self.log(f'Does password match?: {success}')
            return success

    def handle_auth_challenge(self, args):
        """ Start authorization challenge """
        with self.request_lock:
            self.log(f'Received authorization challenge: {args}')

    """ === HANDLERS === """

    def handle_new_connection(self, new_connection, ip_address, ip_port):
        """
        Add new connections to the list of all active connections. Pass:
            - New connection socket
            - Ip address and port connection of client
            - panic_queue.put_nowait for ConnectionClient threads to panic to
            - log file reference
        """
        self.all_client_connections.append(
            ClientConnection(new_connection, ip_address, ip_port, self.panic_queue.put_nowait, self.log_file))
        self.all_client_connections[-1].start()

    """ === GETTERS === """

    def get_status(self):
        status = f'===== SERVER STATUS =====\n' \
                 f'{self.get_num_connections()} Client Connections\n' \
                 f'{"All" if self.are_connections_functional() else "NOT ALL"} Client Connections are Functional\n' \
                 f'Watchdog is {"alive" if self.is_watchdog_alive() else "dead!"}'
        return status

    def get_num_connections(self):
        return copy(len(self.all_client_connections))

    def are_connections_functional(self):
        for connection in self.all_client_connections:
            if not connection.is_functional():
                self.log(f'Connection {connection.name} is not functional!')
                return False
        else:
            # Verified that all active client connections (if any) are functional
            return True

    def is_watchdog_alive(self):
        try:
            return self.connection_watcher.is_alive()
        except AttributeError:
            self.log(f'Connection watcher is not an active thread! Is type: {type(self.connection_watcher)}')
            return False

    """ === SETTERS === """

    def start_watchdog(self):
        self.connection_watcher = Thread(target=self.watch_thread, args=(self, self.panic_queue.get_nowait))
        self.connection_watcher.start()

    def kill_watchdog_thread(self):
        self.watchdog_is_alive = False
        self.kill_watchdog = True
        kill_thread(self.log, self.connection_watcher)

    def restart_watchdog_thread(self):
        self.kill_watchdog_thread()
        self.start_watchdog()

    def start_request_handler(self):
        self.request_handler = Thread(target=self.request_thread, args=(self,))
        self.request_handler.start()

    def kill_request_thread(self):
        self.request_is_alive = False
        self.kill_request = True
        kill_thread(self.log, self.request_handler)

    def restart_request_handler(self):
        self.kill_request_thread()
        self.start_request_handler()

    def kill_connection(self, ip_address, ip_port):
        kill_name = f'{ip_address}:{ip_port}'
        for connection in self.all_client_connections:
            if connection.name == kill_name:
                self.log(f'Killing client connection {connection.name}')
                return connection.cleanup()
        self.log(f'Could not find connection {ip_address}:{ip_port}!')

    def kill_all_connections(self):
        self.log('Killing all connections')
        for connection in self.all_client_connections:
            connection.cleanup()

    def kill_all_connections_except_me(self, ip_address, ip_port):
        self.log(f'Killing all connections except: {ip_address}:{ip_port}!')
        my_name = f'{ip_address}:{ip_port}'
        for connection in self.all_client_connections:
            if connection.name != my_name:
                self.log(f'Killing client connection {connection.name}')
                connection.cleanup()

    def re_init(self):
        self.cleanup()
        self.__init__(self.log_file)

    """ === MISC === """

    def log(self, log):
        self._log(f'[{self.name}] {log}')

    """ === CLEANUP === """

    def cleanup(self):
        """
        Clean-up method will:
            - Call cleanup on all client connections
            - Terminate watchdog thread
        """
        self.log('Cleanup Beginning')
        self.kill_all_connections()
        self.kill_watchdog_thread()
        self.kill_request_thread()
        self.log('Cleanup End')
