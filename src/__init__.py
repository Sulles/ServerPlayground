import os
import sys

# noinspection PyUnresolvedReferences
from multiprocessing import Queue, RLock

sys.path.append(os.path.dirname(os.path.realpath(__file__)))

""" GLOBAL VARIABLES """

MAX_QUEUE_SIZE = 250
SERVER_MAX_POP = 200

""" SERVICE CREATION """

from .lib.Service import SecureService, InsecureService

SECURE_SERVICE = SecureService()
INSECURE_SERVICE = InsecureService()

""" THIRD PARTY REGISTRATION """

from .third_party_services.demo import demo_service

SECURE_SERVICE.register_service('demo', demo_service)
