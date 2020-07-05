import os
import sys

# noinspection PyUnresolvedReferences
from multiprocessing import Queue, RLock

sys.path.append(os.path.dirname(os.path.realpath(__file__)))

from .lib.Service import SecureService, InsecureService

SECURE_SERVICE = SecureService()
INSECURE_SERVICE = InsecureService()
