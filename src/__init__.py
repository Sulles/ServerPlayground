import os
import sys

sys.path.append(os.path.dirname(os.path.realpath(__file__)))

""" =============== GENERAL UTILITY CLASSES AND FUNCTIONS =============== """

MAX_QUEUE_SIZE = 5

from .lib.util import SecureService, InsecureService

SECURE_SERVICE = SecureService()
INSECURE_SERVICE = InsecureService()
