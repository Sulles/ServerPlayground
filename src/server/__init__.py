""" Import for downstream files to minimize duplicate importing """
import os
import sys
# noinspection PyUnresolvedReferences
from multiprocessing import Queue, RLock
# noinspection PyUnresolvedReferences
from threading import Thread
# noinspection PyUnresolvedReferences
from time import time, sleep

sys.path.append(os.path.dirname(os.path.realpath(__file__)))

""" GLOBAL VARIABLES """

MAX_QUEUE_SIZE = 250
SERVER_MAX_POP = 200

""" SERVICE CREATION """

from ..lib.Service import AdminService, InsecureService, RegisteredService, SecureService

INSECURE_SERVICE = InsecureService()
SECURE_SERVICE = SecureService()
REGISTERED_SERVICE = RegisteredService()
ADMIN_SERVICE = AdminService()

""" THIRD PARTY REGISTRATION """

from ..third_party_services.demo import demo_service

""" 
================================= !!!  WARNING !!! =================================
Demo service registered as an INSECURE service for purposes of the demo, it is 
    HIGHLY ADVISABLE to NOT expose services to all unauthorized connections
"""
INSECURE_SERVICE.register_service('demo', demo_service)
