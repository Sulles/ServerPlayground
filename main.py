"""
Main file that should be called to run the server.
"""

from src.server.Gateway import Gateway

if __name__ == "__main__":
    print('Start')

    gateway = Gateway()
    try:
        gateway.start_socket_thread()
        # TODO: Remove timeout time to run indefinitely
        # gateway.main(timeout=30)
        gateway.main()

    except KeyboardInterrupt:
        print('--- Keyboard interrupt detected, stopping server ---')

    finally:
        gateway.cleanup()

        print('Fin')
        exit()
