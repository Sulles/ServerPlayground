"""
Main file that should be called to run the server.
"""

from src import server


if __name__ == "__main__":
    print('Start')

    gateway = server.Gateway()
    gateway.start()
    # TODO: Remove timeout time to run indefinitely
    gateway.main(timeout=30)
    gateway.cleanup()

    print('Fin')
    exit()
