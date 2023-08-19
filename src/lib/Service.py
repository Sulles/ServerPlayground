"""
=============== SERVICES ===============
This file houses the global Service class definitions that all components can interact with.
Two subclasses, InsecureService and SecureService are differentiations of the base Service class meant to hide/provide
    security-dependent APIs to users.

Both objects, InsecureService and SecureService are initialized in src.__init__ and accessible to all components,
    so be careful when registering functions/methods to specific services


=== Service Architecture ===
Services work as a data-forwarding system where data in the form of a dictionary is passed to a callback function

    !!!WARNING!!!
    Call_back functions should be mutex protected to prevent multiple simultaneous access requests by different users.

Data passed to a Service object must be a Dictionary and have the following keys: request, data.
    Optional keys: client_id, command_id
        - or any other field necessary to process the service request successfully

The data dictionary handled by the service will be returned with an additional 'response' field. The 'response' field
    is what should be communicated back to the client, data is kept within the dictionary as a means of tracking
    command/response handling.
Chaining services is feasible and the data dictionary from a previous service call should be appended to a List called
    'previous_services'.

:: Example of service definition:
    def my_service(self, data: dict = None):
        with self.mutex_lock:
            # handle data
            return response

:: Example of service registration:
    INSECURE_SERVICE.register_service('my_service_name', self.my_service)

"""

from . import Queue, RLock
from .util import LogWorthy, lockable
from ..server import MAX_QUEUE_SIZE


class Service(LogWorthy):
    def __init__(self, name, file_name=None):
        """ Service object is a glorified Queue that properly triages requests based on registered endpoints
        :param name: name of service object
        """
        LogWorthy.__init__(self, file_name)
        self.name = name
        self.file_name = file_name
        self.lock = RLock()
        self.services = dict()
        self.oneshots = dict()
        self.queue = Queue(maxsize=MAX_QUEUE_SIZE)
        self.register_service('echo', self.echo)
        self.register_service('help', self.get_help)

    @lockable
    def register_service(self, service_name: str, call_back: classmethod):
        self.log(f'Registering endpoint: {service_name}')
        self.services[service_name] = call_back

    @lockable
    def unregister_service(self, service_name: str):
        try:
            self.log(f'Unregistering endpoint: {service_name}')
            del self.services[service_name]
        except KeyError:
            pass

    # @lockable
    # def create_oneshot(self, oneshot_name, call_back):
    #     self.log(f'Creating oneshot: {oneshot_name}')
    #     self.oneshots[oneshot_name] = call_back
    #
    # @lockable
    # def delete_oneshot(self, oneshot_name):
    #     self.log(f'Deleting oneshot: {oneshot_name}')
    #     del self.oneshots[oneshot_name]

    """ === HANDLER === """

    @lockable
    def _handle(self, data: dict = None):
        self.debug('Got into handler...')
        if data is None or type(data) is not dict:
            self.log(f'Invalid service data, got: {data} of type: {type(data)}')
            return data

        if 'request' not in data.keys() or 'data' not in data.keys():
            data['response'] = 'ERROR: Service request dictionary must have "request" and "data" fields'
            return data

        self.log(f'Got service request: {data["request"]} with data: {data["data"]}')
        if data['request'] in self.services.keys():
            response = self.services[data['request']](data)
            self.debug(f'Got response:\n{response}')
            return response
        else:
            self.log('Got unknown request, returning help')
            return self.get_help(data)
        # else:
        #     self.log(f'Got service request: {data}')
        #     if data in self.services.keys():
        #         response = self.services[data]()
        #         self.debug(f'Got response:\n{response}')
        #         return response
        #     else:
        #         self.log(f'Got unknown data {data}, returning help')
        #         return self.get_help()

    """ === GETTERS === """

    @lockable
    def get_services(self):
        return self.services.keys()

    # @lockable
    # def get_oneshots(self):
    #     return self.oneshots.keys()

    """ === DEFAULT SERVICES === """

    @staticmethod
    def echo(data: dict = None):
        data['response'] = data['data']
        return data

    def get_help(self, data: dict = None):
        help_data = f'=== {self.name} Help ===\n'
        if data is not None and 'client_id' in data.keys():
            help_data += f'Your connection is at: {data["client_id"]}\n'
        help_data += 'Available services:\n'
        for _ in self.services.keys():
            help_data += f'\t{_}\n'
        help_data += f'\texit\n'  # Exit handled by ClientConnection object
        help_data += '\n'
        help_data += 'Commands are space delimited\n'
        help_data += 'I.e. "echo hello world", "echo" is the service name,\n' \
                     'and "hello world" is data passed to the service'
        data['response'] = help_data
        return data

    """ === MISC === """

    def log(self, log):
        self._log(f'[{self.name}] {log}')

    def debug(self, log):
        self._debug(f'[{self.name}] {log}')


class InsecureService(Service):
    """ Insecure Service object that houses all insecure services for users who do not have a login """

    def __init__(self, name: str = None, file_name: str = None):
        self.name = "InsecureService" if name is None else name
        Service.__init__(self, self.name, file_name)

    def handle(self, data):
        self.debug(f'Handling data: {data}')
        return self._handle(data)


class SecureService(InsecureService):
    """ Secure Service object that houses services available to users who have successfully provided an RSA key """

    def __init__(self, name: str = None, file_name: str = None):
        self.name = "SecureService" if name is None else name
        InsecureService.__init__(self, self.name, file_name)

    def handle(self, data: dict = None):
        self.debug(f'Handling data: {data}')
        return self._handle(data)


class RegisteredService(SecureService):
    """ Registered Service object that houses services to users who have provided a username and password """

    def __init__(self, name: str = None, file_name: str = None):
        self.name = "RegisteredService" if name is None else name
        SecureService.__init__(self, self.name, file_name)

    def handle(self, data: dict = None):
        self.debug(f'Handling data: {data}')
        return self._handle(data)


class AdminService(RegisteredService):
    """ Secure Service object that houses all secure services for admins """

    def __init__(self, name: str = None, file_name: str = None):
        self.name = "SecureService" if name is None else name
        RegisteredService.__init__(self, self.name, file_name)

    def handle(self, data: dict = None):
        self.debug(f'Handling data: {data}')
        return self._handle(data)
