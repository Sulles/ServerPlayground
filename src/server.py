"""
Created: Feb. 15, 2020
Updated: Feb. 18, 2020

Author: Suleyman

=== DETAILS ===
This file houses the following objects:
    - Gateway: Maintains an open connection for clients to connect to the server
    - Server: Maintains and monitors ClientConnections, responsible for authorization
    - Client Connection: Handles processing data received from the client

=== Gateway ===
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

# !/usr/bin/env python3

import socket
import hashlib
import binascii
from copy import copy
from multiprocessing import Queue
from queue import Empty, Full
from random import randint
from threading import Thread
from time import time, sleep

from src.util import LogWorthy, kill_thread

# ==================
# TESTING PLAYGROUND
hello = b'hello'
ihello = int.from_bytes(hello, byteorder='big')
bhello = bytes(ihello.to_bytes(length=len('hello'), byteorder='big'))


# ==================

""" =============== GENERAL UTILITY CLASSES AND FUNCTIONS =============== """

MAX_QUEUE_SIZE = 5

# SECURE GLOBAL REQUESTS
SECURE_GLOBAL_REQUEST_QUEUE = Queue(MAX_QUEUE_SIZE)
SECURE_GET_NEXT_REQUEST = SECURE_GLOBAL_REQUEST_QUEUE.get_nowait
SECURE_MAKE_REQUEST = SECURE_GLOBAL_REQUEST_QUEUE.put_nowait

# SECURE GLOBAL RESPONSES
SECURE_GLOBAL_RESPONSE_QUEUE = Queue(MAX_QUEUE_SIZE)
SECURE_GET_NEXT_RESPONSE = SECURE_GLOBAL_RESPONSE_QUEUE.get_nowait
SECURE_SEND_RESPONSE = SECURE_GLOBAL_RESPONSE_QUEUE.put_nowait

# INSECURE GLOBAL REQUESTS
INSECURE_GLOBAL_REQUEST_QUEUE = Queue(MAX_QUEUE_SIZE)
INSECURE_GET_NEXT_REQUEST = INSECURE_GLOBAL_REQUEST_QUEUE.get_nowait
INSECURE_MAKE_REQUEST = INSECURE_GLOBAL_REQUEST_QUEUE.put_nowait

# INSECURE GLOBAL RESPONSES
INSECURE_GLOBAL_RESPONSE_QUEUE = Queue(MAX_QUEUE_SIZE)
INSECURE_GET_NEXT_RESPONSE = INSECURE_GLOBAL_RESPONSE_QUEUE.get_nowait
INSECURE_SEND_RESPONSE = INSECURE_GLOBAL_RESPONSE_QUEUE.put_nowait


class SocketThread(LogWorthy):
    """
    =============== MAIN SERVER SOCKET THREAD ===============
    SocketThread runs a listener thread that constantly monitors the server's socket for new connections.
    It is responsible for:
        - Starting/Stopping listening thread
        - Pausing/Resuming listening thread
        - Adding new connections to the call_back (here a Queue)
    """

    def __init__(self, log_file, call_back):
        """
        Initializer for SocketThread object
        :param log_file: string name of logging file
        :param call_back: call back function, here Queue.put_nowait
        """
        # General
        self.name = 'SocketThread'
        LogWorthy.__init__(self, log_file)

        # IP constants
        self.ip_address = '127.0.0.1'
        self.ip_port = 8888

        # TCP socket
        self.socket = None
        self.socket_timeout = 0.2
        self.socket_backlog = 2

        # Threading
        self.is_running = False
        self.kill_thread = False
        self.call_back = call_back
        self.listener = None
        self.log('Initialization complete!')

    """ === PROCESS START/STOP === """

    def start(self):
        """ This method recreates and starts the thread """
        self.log('Starting...')

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.ip_address, self.ip_port))
        self.log('Socket successfully bound')

        self.is_running = True
        self.kill_thread = False
        self.listener = Thread(target=self.wait_for_next_connection, args=(self,))
        self.listener.start()
        self.log('Thread successfully started')
        return None

    def stop(self):
        """ This method will kill the thread """
        self.log('Stopping...')

        self.is_running = False
        self.kill_thread = True
        kill_thread(self.log, self.listener)

        self.socket.close()
        self.log('Socket closed')
        return None

    def restart(self):
        """ This method will kill then restart the listener thread """
        self.stop()
        self.start()
        return None

    """ === PROCESS PAUSE/RESUME === """

    def pause(self):
        """ This method will pause the thread """
        self.log('Pausing listener thread')
        self.is_running = False
        return None

    def resume(self):
        """ This method will resume the thread """
        self.log('Resuming listener thread')
        self.is_running = True
        return None

    """ === THREADS === """

    @staticmethod
    def wait_for_next_connection(this):
        """ Threaded listener for new connection """
        while not this.kill_thread:  # kill switch for thread
            try:
                if this.is_running:  # pause/resume switch for thread
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
        if self.is_running and not self.kill_thread and self.listener.is_alive():
            return True
        return False

    """ === MISC === """

    def log(self, log):
        self._log(f'[{self.name}] {log}')


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

        # IP constants
        self.ip_address = '127.0.0.1'
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
        self.secure_request_lookup = dict(
            gateway_stop_listener=self.stop,
            gateway_start_listener=self.start,
            gateway_restart_listener=self.socket_thread.restart,
            status=self.get_status,
            gateway_status=self.get_status,
            server_status=self.get_server_status,
            server_kill_connection=self.server.kill_connection,
            server_kill_all_connections=self.server.kill_all_connections,
            server_kill_all_connections_except_me=self.server.kill_all_connections_except_me,
            server_kill_watchdog=self.server.kill_watchdog_thread,
            server_start_watchdog=self.server.start_watchdog,
            server_restart_watchdog=self.server.restart_watchdog_thread
        )

    """ === LISTENER START/STOP === """

    def start(self):
        self.socket_thread.start()

    def stop(self):
        self.socket_thread.stop()

    """ === MAIN === """

    def main(self, timeout=None):
        """
        Main runner method of the Gateway, is responsible for:
            - Monitoring connection_queue for new connections and triaging them to CLI or Server
            - Monitoring response_callback for new responses to send
            - Handling CLI data requests
        """
        if timeout is not None:
            self.log(f'Starting timed main loop for {timeout} seconds')
            end_time = time() + timeout
        else:
            self.log('Starting infinite main loop!')
            end_time = -1

        while time() < end_time:
            # Try and get a new connection
            try:
                (connection, (ip, port)) = self.connection_queue.get(block=False)
                self.log(f'Got new connection at {ip}:{port}')
                self.server.handle_new_connection(connection, ip, port)
            except Empty:
                pass
            except Exception as e:
                self.log('CRITICAL ERROR 1: Failed to get new connection from connection_queue!')
                raise e

            # Check global request queue
            try:
                request = SECURE_GET_NEXT_REQUEST()
                self.log(f'Found secure request in the global queue: {request}')
                self.handle_secure_request(request)
            except Empty:
                pass

            # self.log('Sleeping for a hot second')
            self.log('.')
            sleep(1)

    """ === HANDLERS === """

    def handle_secure_request(self, request):
        if type(request) is dict and request['command'] in self.secure_request_lookup.keys():
            try:
                if 'args' in request.keys():
                    response = self.secure_request_lookup[request['command']](request['args'])
                else:
                    response = self.secure_request_lookup[request['command']]()
                SECURE_SEND_RESPONSE(dict(response=response, id=request['id']))
            except TypeError:
                self.log('Failed to execute ')
        else:
            # If command is not in request lookup, put back in queue
            SECURE_MAKE_REQUEST(request)

    """ === GETTERS === """

    def get_status(self):
        status = f'===== GATEWAY STATUS =====\n' \
                 f'Listener Thread is {"alive" if self.socket_thread.is_functional() else "dead!"}\n' \
                 f'{self.server.get_num_connections()} Active Client Connections'
        return status

    def get_server_status(self):
        return self.server.get_status()

    """ === SETTERS === """

    """ === MISC === """

    def log(self, log):
        self._log(f'[{self.name}] {log}')

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
        self.stop()
        self.server.cleanup()
        self.log('Cleanup End')


class ClientConnection(LogWorthy):
    """
     =============== CLIENT CONNECTION ===============
    The ClientConnection object will handle receiving data from the client and determining what to do with it.
    It is responsible for:
        - Waiting for new data
        - Processing data received on the connection
        - Closing the connection on clean-up
        - Using a call back to add data to the SQL database
        - Sending data to the client connection
    """

    def __init__(self, socket_connection, ip_address, ip_port, panic_call_back, log_file=None):
        """
        Initializer of ClientConnection object
        :param socket_connection: a socket connection object
        :param ip_address: string ip address of the client
        :param ip_port: int port that the client is connected to
        :param panic_call_back: call_back to queue that tells watchdog to kill this connection
        :param log_file: string of log file
        """
        # General
        self.name = f'{ip_address}:{ip_port}'
        LogWorthy.__init__(self, log_file)

        # Connection to Client
        self.connection = socket_connection
        self.connection.settimeout(0.5)
        self.ip_address = ip_address
        self.ip_port = ip_port

        # Multiprocessing
        self.panic_call_back = panic_call_back
        self.kill_thread = False
        self.is_running = True
        self.listener = None
        self.new_data = Queue(MAX_QUEUE_SIZE)
        self.processor = None
        self.response_data = Queue(MAX_QUEUE_SIZE)
        self.responder = None
        self.stop_me = False

        # Client request handling
        self.global_request_timeout = 4
        self.expected_data_pipe = None
        self.insecure_request_lookup = dict(
            login=self.handle_login
        )

        # Security
        self.is_secure = False      # If the client is using symmetric key encryption
        self.is_admin = False       # Client is using symmetric key encryption and has provided an admin password

        self.log('Successfully finished initialization')

    def panic(self):
        self.panic_call_back(self.name)

    """ === PROCESS START/STOP === """

    def start(self):
        """
        Starting method for ConnectionClient. Is responsible for:
            - Initializing processor and listener thread
            - Starting processor and listener thread
        """
        self.is_running = True

        self.listener = Thread(target=self.listen, args=(self, self.new_data.put_nowait, self.panic))
        self.listener.start()

        self.processor = Thread(target=self.process_data, args=(self, self.new_data.get_nowait, self.panic,
                                                                self.response_data.put_nowait))
        self.processor.start()

        self.responder = Thread(target=self.respond, args=(self, self.response_data.get_nowait))
        self.responder.start()

    def stop(self):
        """
        Stopper method is responsible for:
            - Dropping kill thread flag for listener and processor threads
            - Closing socket connection to client
        """
        self.log('Stopping...')
        self.is_running = False
        self.kill_thread = True
        self.new_data.close()
        self.response_data.close()
        kill_thread(self.log, self.listener)
        kill_thread(self.log, self.processor)
        kill_thread(self.log, self.responder)
        self.connection.close()
        self.log('Client Connection closed')

    cleanup = stop  # cleanup and stop are equivalent functions here

    """ === THREADS === """

    @staticmethod
    def listen(this, call_back, panic):
        """
        Listener thread for ConnectionClient, is responsible for:
            - Waiting for new data from client
            - Adding data received from client to call_back
        :param this: ConnectionClient self
        :param call_back: New data queue, here ConnectionClient.new_data.put_nowait
        :param panic: Reference to kill queue monitored by Server watchdog
        """
        empty_data_counter = 0
        while not this.kill_thread:
            if this.is_running:
                try:
                    # this.log('Waiting for data from client...')
                    # String cast for security, don't want to evaluate anything sent by a client
                    data = str(this.connection.recv(4096).decode('utf-8')).replace('\r\n', '')
                    try:
                        if empty_data_counter == -1:
                            sleep(1)
                        elif data == '':
                            empty_data_counter += 1
                            this.log('Got empty data!')
                            if empty_data_counter >= 5:
                                empty_data_counter = -1
                                # Got empty data too many times!
                                panic()
                        else:
                            # Reset empty data counter
                            empty_data_counter = 0
                            this.log(f'Got data: {data}')
                            call_back(data)
                    except AssertionError:
                        this.log(f'New data queue may have been closed! Lost data: {data}')
                        panic()
                    except Full:
                        this.log('Got new data queue overflow! Self-terminating!')
                        exit()
                except socket.timeout:
                    # this.log('Socket timed out waiting to receive new data')
                    pass
                except Exception as e:
                    this.log('Got error while getting data from client!')
                    raise e

    @staticmethod
    def process_data(this, get_new_data, panic, send_response):
        """
        Processor thread for ConnectionClient, is responsible for:
            - Handling all new data from client (passed through ConnectionClient.new_data queue)
        :param this: ConnectionClient self
        :param get_new_data: ConnectionClient.new_data queue.get_nowait
        :param panic: Reference to kill queue monitored by Server watchdog
        :param send_response: ConnectionClient.response
        """
        while not this.kill_thread:
            if this.is_running:
                try:
                    data = get_new_data()
                    this.log(f'Processing data: {data}')
                    try:
                        if this.expected_data_pipe is not None:
                            this.log(f'Sending data to expected data pipe: {this.expected_data_pipe}')
                            this.expected_data_pipe(this, data, send_response, panic)
                        elif this.is_secure or this.is_admin:
                            this.handle_secure_data(this, data, send_response, panic)
                        else:
                            this.handle_insecure_data(this, data, send_response, panic)
                    except AssertionError:
                        this.log(f'Response queue may have been closed! Lost data: {data}')
                        panic()
                    except Full:
                        this.log('Got response data queue overflow! Self-terminating!')
                        panic()
                except Empty:
                    this.log('Got no data, sleeping')
                    sleep(1)
                except Exception as e:
                    this.log('Got error while processing user data!')
                    raise e

    @staticmethod
    def handle_insecure_data(this, data, send_response, panic):
        this.log(f'Insecurely processing {data}')
        # Handle kill request
        for exit_call in ['exit', 'kill', 'leave', 'quit', 'stop']:
            if exit_call in data.lower():
                this.log(f'Received insecure request to terminate client connection with command {exit_call}')
                panic()

        # Handle internal requests
        if data in this.insecure_request_lookup.keys():
            this.insecure_request_lookup[data](this)

        # Handle all other scenarios
        else:
            request_id = randint(0, 255)
            INSECURE_MAKE_REQUEST(dict(id=request_id, command=data))
            timeout = time() + this.global_request_timeout
            backlog_responses = list()
            while time() < timeout:
                try:
                    response = INSECURE_GET_NEXT_RESPONSE()
                    if type(response) is dict:
                        if response['id'] == request_id:
                            this.log(f'Got global response: {response}')
                            if response['response'] is None:
                                send_response('Successfully processed command')
                            else:
                                send_response(response['response'])
                        else:
                            # If response id does not match, keep in backlog temporarily
                            backlog_responses.append(response)
                    return  # Done processing client request, get out of here
                except Empty:
                    # Put all backlog responses back in queue
                    for backlog in backlog_responses:
                        INSECURE_SEND_RESPONSE(backlog)
                    this.log('Waiting for response to insecure global request...')
                    sleep(1)
                except KeyError as e:
                    this.log(f'KeyError, Failed to process data correctly, got error:\n{e}')
                except AttributeError as e:
                    this.log(f'AttributeError?\n{e}')
                except Exception as e:
                    this.log('Got error while handling data')
                    raise e

    @staticmethod
    def handle_secure_data(this, data, send_response, panic):
        this.log(f'Securely processing {data}')
        # Handle kill request
        if [_ in data.lower() for _ in ['exit', 'kill', 'leave', 'quit', 'stop']]:
            this.log('Received secure request to terminate client connection')
            return panic()

        # Handle all other scenarios
        request_id = randint(0, 255)
        SECURE_MAKE_REQUEST(dict(id=request_id, command=data))
        timeout = time() + this.global_request_timeout
        backlog_responses = list()
        while time() < timeout:
            try:
                response = SECURE_GET_NEXT_REQUEST()
                if type(response) is dict:
                    if response['id'] == request_id:
                        this.log(f'Got global response: {response}')
                        if response['response'] is None:
                            send_response('Successfully processed command')
                        else:
                            send_response(response['response'])
                    else:
                        backlog_responses.append(response)
                return  # Done processing client request, get out of here
            except Empty:
                # Put all backlog responses back in queue
                for backlog in backlog_responses:
                    SECURE_SEND_RESPONSE(backlog)
                this.log('Waiting for response to secure global request...')
                sleep(1)
            except KeyError as e:
                this.log(f'KeyError, Failed to process data correctly, got error:\n{e}')
            except AttributeError as e:
                this.log(f'AttributeError?\n{e}')
            except Exception as e:
                this.log('Got error while handling data')
                raise e

    @staticmethod
    def respond(this, next_response):
        while not this.kill_thread:
            if this.is_running:
                try:
                    response = next_response()
                    this.log(f'Trying to send response: {response}')
                    [this.connection.sendall(str(r + '\r\n').encode('utf-8')) for r in response.splitlines()]
                except Empty:
                    pass
                except OSError:
                    this.log('Socket connection has been closed!')
                except Exception as e:
                    this.log('Got error while trying to transmit data')
                    raise e

    """ === THREADED HANDLERS === """

    @staticmethod
    def handle_login(this):
        # TODO: Only allow admin login if connection is secure
        this.log('Client wants to login')
        this.response_data.put_nowait('Enter password')
        # Next data should be password, pass as an insecure request
        this.expected_data_pipe = this.handle_login_verification

    @staticmethod
    def handle_login_verification(this, pwd, send_response, panic):
        this.log('Verifying password...')
        this.expected_data_pipe = None
        # Handle all other scenarios
        request_id = randint(0, 255)
        this.log('Sending external INSECURE request for login verification')
        INSECURE_MAKE_REQUEST(dict(id=request_id, command='verify_admin_pwd', args=pwd))
        # This method is only called when it is expected, so reset the expected data pipe
        timeout = time() + this.global_request_timeout + 5
        while time() < timeout:
            backlog_responses = list()
            try:
                response = INSECURE_GET_NEXT_RESPONSE()
                if type(response) is dict and response['id'] == request_id:
                    this.log(f'Got response: {response}')
                    if response['response']:
                        this.is_admin = True
                        send_response(f'Hello Suleyman! Admin privileges granted to client connection at '
                                      f'{this.ip_address}:{this.ip_port}')
                        return
                    else:
                        this.is_admin = False
                        send_response('Login failed')
                        return
                else:
                    backlog_responses.append(response)
            except Empty:
                # Send all backlog responses that did not match with what we expected
                for backlog in backlog_responses:
                    INSECURE_SEND_RESPONSE(backlog)
                this.log('Waiting 1 second for login verification')
                sleep(1)
        panic()

    @staticmethod
    def handle_auth_challenge_request(this, challenge_request_data, send_response, panic):
        """
        When a client connection wants to be authorized, it will first request a server authentication challenge. Pass
        this data to server as an insecure request
        """
        this.log(f'Sending server insecure request for auth challenge')
        request_id = randint(0, 255)
        INSECURE_MAKE_REQUEST(dict(id=request_id, command='auth_challenge', args=[challenge_request_data]))
        timeout = time() + this.global_request_timeout + 5
        while time() < timeout:
            backlog_responses = list()
            try:
                response = INSECURE_GET_NEXT_RESPONSE()
                if type(response) is dict and response['id'] == request_id:
                    this.log(f'Got response: {response}')
                    send_response(response['response'])
                    return
                else:
                    backlog_responses.append(response)
            except Empty:
                # Send all backlog responses that did not match with what we expected
                for backlog in backlog_responses:
                    INSECURE_SEND_RESPONSE(backlog)
                this.log('Waiting 1 second for login verification')
                sleep(1)
        panic()

    """ === GETTERS === """

    def is_functional(self):
        self.log('Checking if all threads are running...')
        for thread in [self.listener, self.processor]:
            try:
                # If thread is not initialized, or thread is dead, return False (threads are NOT running!)
                if thread is None or not thread.is_alive():
                    return False
            except Exception as e:
                self.log(f'Got error on check for thread aliveness:\n{e}')
                return False
        self.log('All threads are running!')

        if not self.is_running or self.kill_thread:
            self.log('In the process of killing threads!')
            return False

        # Got through all checks, return true
        return True

    """ === SETTERS === """

    """ === MISC === """

    def log(self, log):
        self._log(f'[{self.name}] {log}')


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

        # Connections
        self.all_client_connections = list()

        # Client Connection watcher thread
        self.panic_queue = Queue()
        self.kill_watchdog = False
        self.run_watchdog = True
        self.watchdog_refresh = 0.1  # frequency that watchdog checks on it's threads
        self.watchdog_sleep = 1  # frequency that watchdog checks if it should be running
        self.connection_watcher = None
        self.start_watchdog()

        # Client Connection Insecure Requests thread
        self.kill_request = False
        self.run_request = True
        self.request_refresh = 0.5   # frequency that request handler checks if a new insecure request exists
        self.request_sleep = 1  # frequency that request handler checks if it should be running
        self.insecure_request_lookup = dict(
            verify_admin_pwd=self.verify_admin_password,
            auth_challenge=self.handle_auth_challenge
        )
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
            if this.run_watchdog:
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
            if this.run_request:
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
        self.run_watchdog = False
        self.kill_watchdog = True
        kill_thread(self.log, self.connection_watcher)

    def restart_watchdog_thread(self):
        self.kill_watchdog_thread()
        self.start_watchdog()

    def start_request_handler(self):
        self.request_handler = Thread(target=self.request_thread, args=(self,))
        self.request_handler.start()

    def kill_request_thread(self):
        self.run_request = False
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
