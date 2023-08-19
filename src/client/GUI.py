"""
Created: October 12, 2019

Author: Sulles

=== DESCRIPTION ===
This class houses the main GUI object
"""

from ..lib.util import LogWorthy
from .gui_lib import *


class DefaultWindow(LogWorthy):
    def __init__(self, name, screen_size):
        """
        Constructor for default display window with an input box at the bottom, and display box at the top.
        :param name: String name of the window
        :param screen_size: dictionary with key, value pairs:
            - 'width': int (pixel width of screen)
            - 'height': int (pixel height of screen)
        """
        self.name = name
        LogWorthy.__init__(self)

        input_box_dim = copy(screen_size)
        input_box_dim['height'] = 30
        self.input_box = InputBox([screen_size['width'] - input_box_dim['width']/2,
                                   screen_size['height'] - input_box_dim['height']/2],
                                  width=input_box_dim['width'], height=input_box_dim['height'],
                                  font_to_pixel=FONT_TO_PIXEL_FACTOR)

        display_box_dim = copy(screen_size)
        display_box_dim['height'] -= input_box_dim['height']
        display_box_dim['width'] = 0
        self.stacking_boxes = StackingBoxes(display_box_dim, width=screen_size['width'])

    def __cmp__(self, other):
        """ Only use name for comparison """
        return self.name == other

    def __str__(self):
        """ Only use name for string """
        return self.name

    def draw(self, surface):
        """ Pass drawing to the list object """
        self.stacking_boxes.draw(surface)
        self.input_box.draw(surface)

    def handle_action(self, action_type, action_data=None, mouse_pos=None, key=None):
        """
        TODO: This...
        :param action_type:
        :param action_data:
        :param mouse_pos: 
        :param key: 
        :return: 
        """
        if action_type == 'ADD_TEXT':
            self.stacking_boxes.handle_action(action_type, action_data)
        else:
            self.input_box.handle_action(action_type, mouse_pos=mouse_pos, key=key)

    @staticmethod
    def handle_escape():
        """ transition to main_menu state on when escape is pressed """
        # self.cleanup()    TODO: This...
        return None

    def log(self, log):
        self._log(log)


class GUI(LogWorthy):
    def __init__(self, screen_size):
        """
        Constructor for the entire GUI
        """
        self.name = 'GUI2'
        LogWorthy.__init__(self)

        # Misc
        self.screen_size = screen_size

        # Creating all Menus/States
        self.all_states = dict(default=DefaultWindow('default_window', screen_size))
        self.name_to_state_map = dict(DefaultWindow='default')
        self.state = self.all_states['default']

    def __cmp__(self, other):
        """ Only use name for comparison """
        return self.name == other

    def __str__(self):
        """ Only use name for string """
        return self.name

    def transition_state(self, new_state_name):
        if new_state_name not in self.all_states.keys():
            print('INVALID GUI2 STATE: {}'.format(new_state_name))
        print('GUI2 transitioning state to: {}'.format(new_state_name))
        self.state = self.all_states[new_state_name]

    def draw(self, surface):
        """
        Main draw handler
        :param surface: PyGame surface object
        :return: None, will raise error if fails
        """
        try:
            if self.state is not None:
                self.state.draw(surface)
        except Exception as e:
            print('GUI2 is in state: "{}" when the following error was created: {}'.format(self.state.name, e))
            raise

    # def step(self):
    #     """
    #     The main stepper for all networks
    #     :return: None, will raise error if fails
    #     """
    #     # We only care about stepping for the Normal use case
    #     if self.state is not None and self.state.name == 'Normal':
    #         self.state.step()

    def handle_action(self, action_type, action_data=None, mouse_pos=None, key=None):
        """
        Main action handler
        :param action_type: String which describes the type of action that needs to be handled
        :param action_data: Miscellaneous data for the corresponding action requested
        :param mouse_pos: [x, y] pixel position of the mouse
        :param key: PyGame event.key object for user input
        :return: None, will raise error if fails
        """
        self.log(f'Handling action: {action_type} with data: {action_data}')
        response = None
        if action_type == 'ESCAPE':
            self.handle_escape()
        elif self.state is not None:
            response = self.state.handle_action(action_type, action_data, mouse_pos, key)
        else:
            raise (AttributeError, 'GUI2 state is None, how???')

        # Handle responses
        if type(response) is dict:
            if 'type' in response.keys() and response['type'] == 'transition_state':
                print('Got GUI2 transition state request from: {}'.format(self.state.name))
                self.transition_state(response['new_state'])
                return None
            # print('GUI got action response: {}'.format(response))
        return response

    def handle_escape(self):
        """ This method is responsible for handling the transition between states for the GUI2 object """
        self.transition_state(self.state.handle_escape())
        # pass

    def log(self, log):
        self._log(log)
