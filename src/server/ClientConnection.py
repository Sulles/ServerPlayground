import socket
from multiprocessing import Queue
from queue import Empty, Full
from random import randint
from threading import Thread
from time import time, sleep

from src.lib.util import LogWorthy, kill_thread
from .. import SECURE_SERVICE, INSECURE_SERVICE
from . import INSECURE_MAKE_REQUEST, INSECURE_GET_NEXT_RESPONSE, INSECURE_SEND_RESPONSE, \
    SECURE_GET_NEXT_REQUEST, SECURE_SEND_RESPONSE, SECURE_MAKE_REQUEST, MAX_QUEUE_SIZE


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
        self.insecure_request_lookup = dict(
            login=self.handle_login
        )

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
    def listen(this, call_back, panic):
        """
        Listener thread for ClientConnection, is responsible for:
            - Waiting for new data from client
            - Adding data received from client to call_back
        :param this: ClientConnection self
        :param call_back: New data queue, here ConnectionClient.new_data.put_nowait
        :param panic: Reference to kill queue monitored by Server watchdog
        """
        empty_data_counter = 0
        while not this.kill_thread:
            if this.is_alive:
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
                except ConnectionResetError:
                    this.log('Client terminated connection, shutting down...')
                    panic()
                    sleep(1)
                except Exception as e:
                    this.log('Got error while getting data from client!')
                    raise e

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
        if data in INSECURE_SERVICE.get_services():
            this.log(f'Found known insecure request {data}')
            # TODO: This won't work until data is separated from service request and arguments
            INSECURE_SERVICE.handle(data)

        # Handle all other scenarios
        else:
            this.log(f'Received unknown insecure request: {data}')
            request_id = randint(0, 255)
            # INSECURE_MAKE_REQUEST(dict(id=request_id, command=data))
            timeout = time() + this.global_request_timeout
            backlog_responses = list()
            while time() < timeout:
                try:
                    # TODO: FINISH TRANSITIONING TO SERVICES INSTEAD OF QUEUES
                    response = dict(id=request_id, response=INSECURE_SERVICE.handle('echo', data))
                    # response = INSECURE_GET_NEXT_RESPONSE()
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
            if this.is_alive:
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

        if not self.is_alive or self.kill_thread:
            self.log('In the process of killing threads!')
            return False

        # Got through all checks, return true
        return True

    """ === SETTERS === """

    """ === MISC === """

    def log(self, log):
        self._log(f'[{self.name}] {log}')
