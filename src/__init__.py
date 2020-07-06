import os
import sys

# noinspection PyUnresolvedReferences
from multiprocessing import Queue, RLock

sys.path.append(os.path.dirname(os.path.realpath(__file__)))

from .lib.Service import SecureService, InsecureService

from .third_party_services.demo import demo_service

SECURE_SERVICE = SecureService()
INSECURE_SERVICE = InsecureService()

### THIRD PARTY REGISTRATION ###
SECURE_SERVICE.register_service('demo', demo_service)
