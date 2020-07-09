"""
Main util file with miscellaneous common variables, functions, and classes
"""

from datetime import datetime


def lockable(func):
    """ Thread/process-safe locking decorator for each instance of an object """

    def wrapper(this, *args, **kwargs):
        """
        Wrapper method takes object and all args/kwargs and forwards to the func(tion) that is being decorated
        :param this: Object reference (self), object MUST have a .lock attribute (ideally RLock) and .debug method
        :param args: arbitrary arguments passed to "func"
        :param kwargs: arbitrary key-word arguments passed to "func"
        :return: whatever "func(*args, **kwargs)" returns normally
        """
        this.debug(f'{func} using lock')
        with this.lock:
            return func(this, *args, **kwargs)

    return wrapper


class LogWorthy(object):
    """ Basic Logging object """

    def __init__(self, file_name=None):
        self.file_name = file_name
        self.log_file = None
        if file_name is not None:
            self.log_file = open(self.file_name, 'a')

    def _log(self, log):
        improved_log = f'[{datetime.now()}] {log}'
        print(improved_log)
        self._debug(log)

    def _debug(self, log):
        if self.file_name is not None:
            log = f'[{datetime.now()}] {log}'
            with self.log_file:
                self.log_file.writelines('\n' + log)


def kill_thread(logger, thread):
    tries = 0
    try:
        while thread.is_alive():
            tries += 1
            thread.join(timeout=1)
            if tries > 3:
                logger('Killing thread ungracefully!')
                thread._stop()
                return
        # logger('Thread closed gracefully')
    except AttributeError as e:
        logger(f'Thread is already closed?\n{e}')
    except RuntimeError as e:
        logger(f'Failed to close with error: {e}')
    except Exception as e:
        logger(f'WUT?')
        raise e
