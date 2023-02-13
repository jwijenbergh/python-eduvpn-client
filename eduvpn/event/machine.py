from enum import IntEnum
from typing import Any, Callable, Dict, List, Tuple

from eduvpn.event.state import State, StateType

# The attribute that callback functions get
EDUVPN_CALLBACK_PROPERTY = "_eduvpn_property_callback"

# There are very few transitions here because most are defined in the go library
TRANSITIONS = {
    State.MAIN: {
        State.ASK_LOCATION: "Go to ask location",
        State.CONNECTED: "Go to connected",
    },
    State.ASK_LOCATION: {
        State.MAIN: "Go back or error",
    },
    State.GOT_CONFIG: {
        State.DISCONNECTED: "Go to disconnected",
    },
    State.DISCONNECTING: {
        State.DISCONNECTED: "Done disconnecting",
    },
    State.DISCONNECTED: {
        State.CONNECTING: "OS reports it is trying to connect",
        State.MAIN: "User wants to choose a new server",
    },
    State.CONNECTING: {
        State.DISCONNECTED: "Cancel or error",
        State.CONNECTED: "Done connecting",
    },
    State.CONNECTED: {
        State.DISCONNECTING: "App wants to disconnect",
    },
}

# Transitions is a map from a state to a list of states and descriptions for the transition
Transitions = dict[State, dict[State, str]]


def class_state_transition(state: int, state_type: StateType) -> Callable:
    """A decorator to be internally by classes to register the event
    :param state: int: The state of the transition
    :param state_type: StateType: The type of transition
    :meta private:
    """

    def wrapper(func):
        """
        :param func: The function to set the internal attribute for
        """
        setattr(func, EDUVPN_CALLBACK_PROPERTY, (state, state_type))
        return func

    return wrapper


class EventHandler(object):
    """The class that neatly handles event callbacks"""

    def __init__(self):
        self.handlers: Dict[Tuple[int, StateType], List[Callable]] = {}

    def change_class_callbacks(self, cls: Any, add: bool = True) -> None:
        """The function that is used to change class callbacks
        :param cls: Any: The class to change the callbacks for
        :param add: bool:  (Default value = True): Whether or not to add or remove the event. If true the event gets added
        :meta private:
        """
        # Loop over method names
        for method_name in dir(cls):
            try:
                # Get the method
                method = getattr(cls, method_name)
            except:
                # Unable to get a value, go to the next
                continue

            # If it has a callback defined, add it to the events
            method_value = getattr(method, EDUVPN_CALLBACK_PROPERTY, None)
            if method_value:
                state, state_type = method_value

                if add:
                    self.add_event(state, state_type, method)
                else:
                    self.remove_event(state, state_type, method)

    def remove_event(self, state: int, state_type: StateType, func: Callable) -> None:
        """Removes an event
        :param state: int: The state to remove the event for
        :param state_type: StateType: The state type to remove the event for
        :param func: Callable: The function that needs to be removed from the event
        :meta private:
        """
        for key, values in self.handlers.copy().items():
            if key == (state, state_type):
                values.remove(func)
                if not values:
                    del self.handlers[key]
                else:
                    self.handlers[key] = values

    def add_event(self, state: int, state_type: StateType, func: Callable) -> None:
        """Adds an event
        :param state: int: The state to add the event for
        :param state_type: StateType: The state type to add the event for
        :param func: Callable: The function that needs to be added to the event
        :meta private:
        """
        if (state, state_type) not in self.handlers:
            self.handlers[(state, state_type)] = []
        self.handlers[(state, state_type)].append(func)

    def run_state(
        self, state: IntEnum, other_state: IntEnum, state_type: StateType, data: str
    ) -> bool:
        """The function that runs the callback for a specific event
        :param state: int: The state of the event
        :param other_state: int: The other state of the event
        :param state_type: StateType: The state type of the event
        :param data: str: The data that gets passed to the function callback when the event is ran
        :meta private:
        """
        if (state, state_type) not in self.handlers:
            return False
        for func in self.handlers[(state, state_type)]:
            func(other_state, data)
        return True

    def run(self, old_state: IntEnum, new_state: IntEnum, data: Any) -> bool:
        """Run a specific event.
        It converts the data and then runs the event for all state types
        :param old_state: int: The previous state for running the event
        :param new_state: int: The new state for running the event
        :param data: Any: The data that gets passed to the event
        :param convert: bool:  (Default value = True): Whether or not to convert the data further
        """
        # First run leave transitions, then enter
        self.run_state(old_state, new_state, StateType.LEAVE, data)
        # We decide handled based on enter transitions
        handled = self.run_state(new_state, old_state, StateType.ENTER, data)
        return handled


class StateMachine:
    def __init__(self, transitions: Transitions):
        self.event_handler: EventHandler = EventHandler()
        self.current: State = State.INITIAL
        self.transitions: Transitions = transitions

    def register_events(self, cls: Any):
        self.event_handler.change_class_callbacks(cls)

    @property
    def current_transitions(self):
        return self.transitions.get(self.current, {})

    def has_back(self):
        if self.current == State.MAIN:
            return False
        return State.MAIN in self.current_transitions

    def back(self):
        self.go(State.MAIN, go_transition=True)

    def go(self, state: State, data: Any = None, go_transition: bool = False):
        if not go_transition and state not in self.current_transitions:
            # Self transitions are a quiet fail
            if state == self.current:
                return
            raise Exception(
                f"State transition not possible to state: {state}, current state: {self.current}"
            )
        old_state = self.current
        self.current = state
        self.event_handler.run(old_state, state, data)
