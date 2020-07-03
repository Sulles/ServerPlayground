"""
Main file that should be called to run the server.
"""

from src.server.Gateway import Gateway

if __name__ == "__main__":
    print('Start')

    gateway = Gateway()
    gateway.start()
    # TODO: Remove timeout time to run indefinitely
    gateway.main(timeout=30)
    gateway.cleanup()

    print('Fin')
    exit()
