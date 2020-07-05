"""
=============== SERVER ===============
This file houses the following objects:
    - Gateway: Maintains an open connection for clients to connect to the server
    - Server: Maintains and monitors ClientConnections, responsible for authorization
    - Client Connection: Handles processing data received from the client
"""

import binascii
import hashlib
from copy import copy
from queue import Empty

from src.lib.util import *
from . import Thread, sleep
from .ClientConnection import ClientConnection
from .. import Queue, RLock, INSECURE_SERVICE, SECURE_SERVICE

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
        self.lock = RLock()
        self.kill_lock = RLock()

        # Client Connection watcher thread
        self.panic_queue = Queue()
        self.kill_watchdog = False
        self.watchdog_is_alive = True
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
        # Client Connection Secure Requests
        SECURE_SERVICE.register_service('list_all_connections', self.list_all_connections)

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
                    kill_name = get_next_panic(timeout=1)
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
                # this.log('Got nothing, trying again')
            else:
                this.log('Not running watchdog, sleeping')
                sleep(this.watchdog_sleep)
        this.log('Client connection watchdog is ending!')

    """ === SERVICES === """

    @lockable
    def verify_admin_password(self, data):
        """ Verify that the provided password is an admin password """
        self.log(f'Verifying password provided matches admin password for client {data["client_id"]}...')
        salt = self.admin_password[:64]
        stored_password = self.admin_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', data['data'].encode('utf-8'), salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        success = pwdhash == stored_password
        self.log(f'Does password match?: {success}')
        if success:
            self.log(f'Attempting to authorize client: {data["client_id"]}')
            authorize_request = dict(client_id=self.name, request=f'authorize_{data["client_id"]}', data=None)
            authorize_response = SECURE_SERVICE.handle(authorize_request)
            data['previous_services'] = [authorize_response]
            data['response'] = authorize_response['response']
            return data
        else:
            data['response'] = f'Failed to authorize user at {data["client_id"]}'
            return data

    @lockable
    def handle_auth_challenge(self, args):
        """ Start authorization challenge """
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

    @lockable
    def get_status(self, data: dict = None):
        status = f'===== SERVER STATUS =====\n' \
                 f'{self.get_num_connections()} Client Connections\n' \
                 f'{"All" if self.are_connections_functional() else "NOT ALL"} Client Connections are Functional\n' \
                 f'Watchdog is {"alive" if self.is_watchdog_alive() else "dead!"}'
        if data is not None:
            data['response'] = status
            return data
        else:
            return status

    @lockable
    def get_num_connections(self, data: dict = None):
        num = str(len(self.all_client_connections))
        if data is not None:
            data['response'] = num
            return data
        else:
            return num

    @lockable
    def list_all_connections(self, data: dict = None):
        if data is not None:
            data['response'] = str([_.name for _ in self.all_client_connections])
            return data
        else:
            return str([_.name for _ in self.all_client_connections])

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

    @lockable
    def start_watchdog(self, data: dict = None):
        self.connection_watcher = Thread(target=self.watch_thread, args=(self, self.panic_queue.get))
        self.connection_watcher.start()
        if data is not None:
            data['response'] = 'Started client watchdog'
            return data

    @lockable
    def kill_watchdog_thread(self, data: dict = None):
        self.watchdog_is_alive = False
        self.kill_watchdog = True
        kill_thread(self.log, self.connection_watcher)
        if data is not None:
            data['response'] = 'Killed client watchdog'
            return data

    def restart_watchdog_thread(self, data: dict = None):
        self.kill_watchdog_thread()
        self.start_watchdog()
        if data is not None:
            data['response'] = 'Restarted client watchdog'
            return data

    def _kill_client(self, client):
        with self.kill_lock:  # use special lock for this for lock certainty
            self.log(f'Killing client connection {client.name}')
            self.all_client_connections.remove(client)
            client.cleanup()

    @lockable
    def kill_connection(self, data: dict):
        client_address = data['data']
        if 'client_id' in data.keys():
            self.log(f'Client {data["client_id"]} requested to kill connection: {client_address}')
        # Match client_address with all client connections names, which is their address
        for client in self.all_client_connections:
            if client.name == client_address:
                self._kill_client(client)
                data['response'] = f'Killed connection: {client_address}'
                return data
        data['response'] = f'Could not find connection {client_address}!'
        return data

    @lockable
    def kill_all_connections(self, data: dict = None):
        if data is not None and 'client_id' in data.keys():
            self.log(f'Client {data["client_id"]} requested to kill -ALL- connections')
        # Kill all clients
        self.log('Killing all connections')
        for client in copy(self.all_client_connections):
            self._kill_client(client)
        if data is not None:
            data['response'] = 'Killing all connections...'
            return data

    @lockable
    def kill_all_connections_except_me(self, data: dict):
        client_address = data['data']
        for client in copy(self.all_client_connections):
            if client.name != client_address:
                self._kill_client(client)
        if 'client_id' in data.keys():
            data['response'] = f'Client {data["client_id"]} killed all connections EXCEPT: {client_address}'
        else:
            data['response'] = f'Killed all connections EXCEPT: {client_address}!'
        return data

    def re_init(self):
        self.cleanup()
        self.__init__(self.log_file)

    """ === MISC === """

    def log(self, log):
        self._log(f'[{self.name}] {log}')

    def debug(self, log):
        self._debug(f'[{self.name}] {log}')

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
        self.log('Cleanup End')
