"""
Created: Feb. 15, 2020
Updated:

Author: Suleyman

=== DETAILS ===
This file houses the client object responsible for establishing and passing data to the server
"""

# !/usr/bin/env python3

import socket
from multiprocessing import Queue
from threading import Thread
from time import sleep

import pygame
from pygame.locals import *

from .GUI import GUI
from .gui_lib import colors
from ..lib.util import LogWorthy, kill_thread

from ..lib.rsa import *

# HOST = '35.237.14.199'
HOST = '127.0.0.1'
PORT = 8888


class Client(LogWorthy):
    def __init__(self, ip_address, ip_port):
        """
        Initializer of Client object
        :param ip_address: string of server IP address
        :param ip_port: int port of server connection
        """
        # General
        self.name = 'Unknown'
        LogWorthy.__init__(self)

        # GUI
        pygame.init()
        self.gui_data = dict(SCREEN_SIZE=dict(width=500, height=800),
                             FRAME_RATE=30)
        self.fps_clock = pygame.time.Clock()
        self.surface = pygame.display.set_mode((self.gui_data['SCREEN_SIZE']['width'],
                                                self.gui_data['SCREEN_SIZE']['height']))
        self.gui = GUI(self.gui_data['SCREEN_SIZE'])

        # Socket
        self.ip_address = ip_address
        self.ip_port = ip_port
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Multiprocessing
        self.kill_thread = False
        self.is_alive = True
        self.listener = None
        self.new_data = Queue(5)
        self.output = None

        # RSA keys
        self.private_key = PrivateKey()
        self.public_key = None

    def start(self):
        """
        Starting method for Client. Is responsible for:
            - Starting listener thread
            - Starting responder thread
            - Connecting socket to Server
        """
        self.log(f'Establishing connection to {self.ip_address}:{self.ip_port}...')
        self.connection.connect((self.ip_address, self.ip_port))
        self.listener = Thread(target=self.listen, args=(self,))
        self.listener.start()
        self.log('Connection established!')

    def run(self):
        try:
            while True:
                for event in pygame.event.get():
                    response = None

                    """ EXIT CONDITION """
                    if event.type == QUIT:
                        exit(0)

                    # KEY INPUT CONDITION
                    elif event.type == KEYDOWN:
                        if event.key == K_ESCAPE:
                            # self.gui.handle_action('ESCAPE')
                            exit(0)
                        elif event.key == 8:
                            self.gui.handle_action('KEY_DOWN', key=event.key)
                        else:
                            print('Got key input: {}'.format(event.unicode))
                            self.gui.handle_action('KEY_DOWN', key=event.unicode)

                    # MOUSE BUTTON DOWN
                    elif event.type == MOUSEBUTTONDOWN:
                        # RIGHT CLICK
                        if event.button == 3:
                            print('Got RIGHT mouse DOWN')
                            response = self.gui.handle_action('RIGHT_MOUSE_DOWN', mouse_pos=event.pos)
                            print('Got closest obj with name: {}'.format(response))
                        # LEFT CLICK
                        elif event.button == 1:
                            print('Got LEFT mouse DOWN')
                            response = self.gui.handle_action('LEFT_MOUSE_DOWN', mouse_pos=event.pos)
                    #
                    # # MOUSE BUTTON UP
                    # elif event.type == MOUSEBUTTONUP:
                    #     # RIGHT CLICK
                    #     if event.button == 3:
                    #         print('Got RIGHT mouse UP')
                    #         response = dict(type='deselect')
                    #     # LEFT CLICK
                    #     if event.button == 1:
                    #         print('Got LEFT mouse UP')
                    #         response = self.gui.handle_action('LEFT_MOUSE_UP', event.pos)
                    #
                    # # HANDLE RESPONSES
                    # if type(response) is dict:
                    #     print('Got action response: {}'.format(response))
                    #     if 'type' in response.keys():
                    #         if response['type'] == 'terminate':
                    #             terminate()
                    #         elif response['type'] == 'new_selection':
                    #             print('Got new selection...')
                    #             selected_obj = response['object']
                    #         elif response['type'] == 'deselect':
                    #             print('Deselecting current object...')
                    #             selected_obj = None
                    # elif response is not None:
                    #     print('Got unknown response: {}'.format(response))

                # PYGAME SETTINGS
                pygame.display.update()
                self.fps_clock.tick(self.gui_data['FRAME_RATE'])

                # DRAWING
                # Re-draw background
                self.surface.fill(colors['BGCOLOR'])

                # GUI handling
                # GUI.handle_action('MOUSE_HOVER', pygame.mouse.get_pos())
                # self.gui.step()
                self.gui.draw(self.surface)

        except Exception as e:
            print(f'Ran into error while running:\n{e}')
            raise e

        finally:
            self.cleanup()

    def send(self, data):
        if data != '':
            self._send(data)

    def _send(self, data: str):
        self.connection.sendall(data.encode('utf-8'))

    """ === THREADS === """

    @staticmethod
    def listen(this):
        timeout_counter = 0
        while not this.kill_thread:
            if this.is_alive:
                try:
                    data = str(this.connection.recv(4096).decode('utf-8')).replace('\r\n', '')
                    try:
                        print(data)
                        this.gui.handle_action('ADD_TEXT', data)
                    except AssertionError:
                        this.log(f'{this.name} possible data corruption, self-terminating')
                    # except Full:
                    #     this.log(f'{this.name} data overflow, self-terminating')
                except socket.timeout:
                    # this.log('Socket timed out waiting to receive new data')
                    timeout_counter += 1  # socket times out every 0.5s
                    if timeout_counter * 0.5 > this.client_timeout:
                        this.log(f'{this.name} timeout reached, self-terminating')
                    pass
                except UnicodeDecodeError as e:
                    this.log(f'Failed to decode server data with error {e}')
                except ConnectionResetError:
                    this.log(f'Server at {this.ip_address}:{this.ip_port} terminated connection, shutting down...')
                except OSError:
                    this.log(f'Aborted connection')
                # except Exception as e:
                #     this.log(f'Got error while getting data from client!\n{e}')

    """ === MISC === """

    def log(self, log):
        self._log(log)

    def debug(self, log):
        self._debug(log)

    """ === CLEANUP === """

    def cleanup(self):
        try:
            pygame.quit()
            self.is_alive = False
            self.kill_thread = True
            sleep(1)
            self.new_data.close()
            self.connection.close()
            self.connection.detach()
            kill_thread(self.log, self.listener)
        except Exception as e:
            self.log(f'Ungraceful disconnection with error:\n{e}')


if __name__ == "__main__":
    client = Client(HOST, PORT)
    client.start()
    while client.run():
        try:
            inp = input('')
            print(f'Got debugging input: {inp}')
        except KeyboardInterrupt:
            print('--- Keyboard interrupt detected, stopping Client ---')
            client.cleanup()
            exit(0)
    print('Not visible?')
    client.cleanup()
