# findmy/reports/state.py
"""Account login state and base classes for stateful objects."""

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, Generic, TypeVar, cast

from typing_extensions import TypedDict, override

logger = logging.getLogger(__name__)


# --- Original content ---

class LoginState(Enum):
    """Enum of possible login states. Used for :meth:`AppleAccount`'s internal state machine."""

    LOGGED_OUT = 0
    REQUIRE_2FA = 1
    AUTHENTICATED = 2
    LOGGED_IN = 3

    def __lt__(self, other: "LoginState") -> bool:
        """
        Compare against another :meth:`LoginState`.

        A :meth:`LoginState` is said to be "less than" another :meth:`LoginState` iff it is in
        an "earlier" stage of the login process, going from LOGGED_OUT to LOGGED_IN.
        """
        if isinstance(other, LoginState):
            return self.value < other.value

        return NotImplemented

    @override
    def __repr__(self) -> str:
        """Human-readable string representation of the state."""
        return self.__str__()


# --- New definitions required by anisette.py ---

class StateError(Exception):
    """Exception raised for state-related errors."""
    pass


class Closable(ABC):
    """Abstract base class for objects that need to be closed."""

    @abstractmethod
    async def close(self) -> None:
        """Closes any open resources, like network connections."""
        ...


# This TypeVar is unbounded to be compatible with TypedDicts
T = TypeVar("T")


class Serializable(ABC, Generic[T]):
    """Abstract base class for objects that can be serialized to/from JSON."""

    @abstractmethod
    def to_json(self) -> T:
        """Serializes the object's state to a TypedDict."""
        ...

    @classmethod
    @abstractmethod
    def from_json(cls, state: T) -> "Serializable[T]":
        """Deserializes the object from a TypedDict."""
        ...


class State(Generic[T]):
    """A generic wrapper for managing a TypedDict as a state object."""

    _state: T

    def __init__(self, default_state: T) -> None:
        self._state = default_state

    def get(self, key: str) -> Any:
        """Gets a value from the state."""
        # We must cast _state to a dict to use .get()
        return cast(Dict[str, Any], self._state).get(key)

    def set(self, key: str, value: Any) -> None:
        """Sets a value in the state."""
        # We must cast _state to a dict to set a key
        cast(Dict[str, Any], self._state)[key] = value

    def to_json(self) -> T:
        """Returns the underlying state dictionary."""
        return self._state


# --- Base TypedDicts for different states ---

class AccountStateMapping(TypedDict, total=False):
    """State for the main AppleAccount."""
    username: str
    login_state: int
    login_state_data: Dict[str, Any]
    # ... other fields as needed


class AnisetteMapping(TypedDict, total=False):
    """Base state for an AnisetteProvider."""
    # This will be extended by specific providers
    provider_id: str