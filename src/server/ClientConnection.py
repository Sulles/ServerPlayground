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

import socket
from queue import Empty, Full
from threading import Thread
from time import time, sleep

from src.lib.util import LogWorthy, kill_thread, lockable
from . import MAX_QUEUE_SIZE
from .. import SECURE_SERVICE, INSECURE_SERVICE, RLock, Queue


class ClientConnection(LogWorthy):
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
        LogWorthy.__init__(self, log_file)
        self.name = f'{ip_address}:{ip_port}'
        self.lock = RLock()

        # Connection to Client
        self.connection = socket_connection
        self.connection.settimeout(0.5)
        self.ip_address = ip_address
        self.ip_port = ip_port

        # Multiprocessing
        self.panic_call_back = panic_call_back
        self.kill_thread = False
        self.is_alive = True
        self.listener = None
        self.new_data = Queue(MAX_QUEUE_SIZE)
        self.processor = None
        self.response_data = Queue(MAX_QUEUE_SIZE)
        self.responder = None
        self.stop_me = False

        # Client request handling
        self.global_request_timeout = 4
        self.expected_data_pipe = None

        # Security
        self.is_secure = False  # If the client is using symmetric key encryption
        self.is_admin = False  # Client is using symmetric key encryption and has provided an admin password

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
        self.is_alive = True

        self.listener = Thread(target=self.listen, args=(self, self.new_data.put_nowait, self.panic))
        self.listener.start()

        self.processor = Thread(target=self.process_data, args=(self, self.new_data.get, self.panic,
                                                                self.response_data.put_nowait))
        self.processor.start()

        self.responder = Thread(target=self.respond, args=(self, self.response_data.get))
        self.responder.start()

        # Register services
        SECURE_SERVICE.register_service(f'authorize_{self.name}', self.make_admin)

        self.response_data.put_nowait('Welcome to the Playground!')

    def stop(self):
        """
        Stopper method is responsible for:
            - Dropping kill thread flag for listener and processor threads
            - Closing socket connection to client
        """
        self.log('Stopping...')
        SECURE_SERVICE.unregister_service(f'authorize_{self.name}')
        self.is_alive = False
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
    def listen(this, process, panic):
        # def listen(this, call_back, response, panic):
        """
        Listener thread for ClientConnection, is responsible for:
            - Waiting for new data from client
            - Adding data received from client to call_back
        :param this: ClientConnection self
        :param process: New data queue, here ClientConnection.new_data.put_nowait
        # :param response: Response queue, here self.response_data.put_nowait
        :param panic: Reference to kill queue monitored by Server watchdog
        """
        empty_data_counter = 0
        while not this.kill_thread:
            if this.is_alive:
                try:
                    # this.log('Waiting for data from client...')
                    # String cast for security, don't want to evaluate anything sent by a client, TODO: verify this...
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
                            process(data)
                            # response(call_back(data))
                    except AssertionError:
                        this.log(f'New data queue may have been closed! Lost data: {data}')
                        panic()
                    except Full:
                        this.log('Got new data queue overflow! Self-terminating!')
                        panic()
                        sleep(1)
                except socket.timeout:
                    # this.log('Socket timed out waiting to receive new data')
                    pass
                except ConnectionResetError:
                    this.log('Client terminated connection, shutting down...')
                    panic()
                    sleep(1)
                except Exception as e:
                    this.log('Got error while getting data from client!')
                    this.log(e)

    @staticmethod
    def process_data(this, get_new_data, panic, send_response):
        """
        Processor thread for ClientConnection, is responsible for:
            - Handling all new data from client (passed through ClientConnection.new_data queue)
        :param this: ClientConnection self
        :param get_new_data: ClientConnection.new_data queue.get_nowait
        :param panic: Reference to kill queue monitored by Server watchdog
        :param send_response: ClientConnection.response
        """
        while not this.kill_thread:
            if this.is_alive:
                try:
                    raw_data = get_new_data(timeout=1)
                    this.log(f'Processing raw data: {raw_data}')
                    data = this.build_data(this, raw_data)
                    try:
                        # if this.expected_data_pipe is not None:
                        #     this.log(f'Sending data to expected data pipe: {this.expected_data_pipe}')
                        #     this.expected_data_pipe(this, data, send_response, panic)
                        if this.is_secure or this.is_admin:
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
                    # this.log('Got no data, passing')
                    pass
                except (OSError, ValueError):
                    this.log('Thread is dying!')
                    exit(0)
                except Exception as e:
                    this.log('Got error while processing user data!')
                    this.log(e)
                    send_response('ERROR CC_3.0: Unknown Error')

    @staticmethod
    def build_data(this, raw_data):
        data = dict(client_id=this.name, time=round(time(), 2))
        if ' ' in raw_data:
            request_type, request_data = raw_data.split(' ', 1)
            data['request'] = request_type
            data['data'] = request_data
        else:
            data['request'] = raw_data
            data['data'] = None
        return data

    @staticmethod
    def handle_exit(this, data, send_response, panic):
        if data is not None:
            for exit_call in ['exit', 'kill', 'leave', 'quit', 'stop']:
                if exit_call in data.lower()[0:5]:
                    this.log(f'Received request to terminate client connection with command {exit_call}')
                    send_response('Closing connection...')
                    panic()
                    return True
        return False

    @staticmethod
    def handle_insecure_data(this, data, send_response, panic):
        this.log(f'Insecurely processing {data}')
        # Handle kill request
        if this.handle_exit(this, data['request'], send_response, panic):
            sleep(1)
            return

        # Handle internal requests
        response = INSECURE_SERVICE.handle(data)
        this.debug(f'Processed data, got: {response}')
        try:
            send_response(response["response"])
        except ValueError:
            send_response("ERROR CC_1: Internal response data invalid")
        except Exception as e:
            this.log(f'ERROR CC_2: Unexpected transmission error: {e}')

    @staticmethod
    def handle_secure_data(this, data, send_response, panic):
        this.log(f'Securely processing {data}')
        # Handle kill request
        if this.handle_exit(this, data['request'], send_response, panic):
            return

        # Handle all other scenarios
        response = SECURE_SERVICE.handle(data)
        this.debug(f'Processed data, got: {response}')
        try:
            send_response(response["response"])
        except ValueError:
            send_response("ERROR CC_1: Internal response data invalid")
        except Exception as e:
            this.log(f'ERROR CC_2: Unexpected transmission error: {e}')

    @staticmethod
    def respond(this, next_response):
        while not this.kill_thread:
            if this.is_alive:
                try:
                    response = next_response(timeout=1)
                    if type(response) is not str:
                        response = str(response)
                    this.debug(f'Trying to send response: {response}')
                    [this.connection.sendall(str(r + '\r\n').encode('utf-8')) for r in response.splitlines()]
                    this.connection.sendall(str('>> ').encode('utf-8'))
                except Empty:
                    pass
                except OSError:
                    this.log('Socket connection has been closed!')
                except Exception as e:
                    this.log('Got error while trying to transmit data')
                    this.log(e)

    """ === SERVICES === """

    @lockable
    def make_admin(self, data: dict = None):
        self.is_admin = True
        if data is not None:
            data['response'] = f'Admin privileges granted to client connection at {self.name}'
            return data
        else:
            self.response_data.put_nowait(
                f'Admin privileges granted to client connection at {self.name}')

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

        if not self.is_alive or self.kill_thread:
            self.log('In the process of killing threads!')
            return False

        # Got through all checks, return true
        return True

    """ === SETTERS === """

    """ === MISC === """

    def log(self, log):
        self._log(f'[{self.name}] {log}')

    def debug(self, log):
        self._debug(f'[{self.name}] {log}')
