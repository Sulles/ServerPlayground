"""
Main file that should be called to run the server.
"""

import cProfile
import io
from pstats import SortKey, Stats

from src.server.Gateway import Gateway

if __name__ == "__main__":
    print('Start')

    # pr = cProfile.Profile()
    # pr.enable()

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

        # pr.disable()
        # s = io.StringIO()
        # sortby = SortKey.CUMULATIVE
        # ps = Stats(pr, stream=s).sort_stats(sortby)
        # ps.print_stats()
        # print(s.getvalue())

        print('Fin')
        exit()
