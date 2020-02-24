"""
Main util file with miscellaneous common variables, functions, and classes
"""

from datetime import datetime


class LogWorthy:
    def __init__(self, file_name=None):
        self.file_name = file_name

    def _log(self, log):
        log = f'[{datetime.now()}] {log}'
        print(log)
        if self.file_name is not None:
            with open(self.file_name, 'a') as file:
                file.writelines('\n' + log)


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
        logger('Thread closed gracefully')
    except AttributeError as e:
        logger(f'Thread is already closed?\n{e}')
    except RuntimeError as e:
        logger(f'Failed to close with error: {e}')
    except Exception as e:
        logger(f'WUT?')
        raise e
