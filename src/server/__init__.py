""" Import for downstream files to minimize duplicate importing """
import os
import sys
# noinspection PyUnresolvedReferences
from threading import Thread
# noinspection PyUnresolvedReferences
from time import time, sleep

# noinspection PyUnresolvedReferences
from .. import Queue, MAX_QUEUE_SIZE

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
