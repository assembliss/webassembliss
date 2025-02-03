import redis
from typing import Dict
from json import loads, dumps


class DebuggerDB:
    """Class to manage the ports we can use for concurrent debugging sessions."""

    def __init__(
        self,
        *,
        host: str = "redis",
        port: int = 6379,
        min_port: int = 9_999,
        max_port: int = 10_999,
        user_prefix: str = "USER_",
        port_prefix: str = "PORT_",
        init_count: int = 0,
        port_active_token: str = "ACTIVE",
        port_available_token: str = "free",
    ):
        # Create a connection with the db that decodes responses automatically.
        self._db = redis.Redis(host=host, port=port, decode_responses=True)
        # Initialize the required values in the database if they're not there.
        self._db.setnx("MIN_PORT", min_port)
        self._db.setnx("MAX_PORT", max_port)
        self._db.setnx("USER_PREFIX", user_prefix)
        self._db.setnx("PORT_PREFIX", port_prefix)
        # Load the required values from the db, in case another client had overwritten them.
        # These values should not change during execution, so it's fine to have a local copy.
        self._min_port: int = int(self._db.get("MIN_PORT"))  # type: ignore[arg-type]
        self._max_port: int = int(self._db.get("MAX_PORT"))  # type: ignore[arg-type]
        self._user_prefix: str = self._db.get("USER_PREFIX")  # type: ignore[assignment]
        self._port_prefix: str = self._db.get("PORT_PREFIX")  # type: ignore[assignment]
        # Store the number of ports that we can use.
        self._range: int = self._max_port - self._min_port + 1
        self._port_active_token = port_active_token
        self._port_available_token = port_available_token
        # If received a non-zero count, initialize it if it's not set yet.
        if init_count:
            # This is mostly here for webapp-debugging purposes.
            # This value is volatile, so we should not have a copy away from the db.
            self._db.setnx("COUNT", init_count)

    def _user_key(self, user_signature: str) -> str:
        """Create a db-key for user data in a standard manner."""
        return f"{self._user_prefix}{user_signature}"

    def _port_key(self, port: int) -> str:
        """Create a port-key for port data in a standard manner."""
        return f"{self._port_prefix}{port:_}"

    def find_available_port(self, *, user_signature: str) -> int:
        """Return the port this user request should use."""

        # Retrieve data from db.
        data = self._db.get(self._user_key(user_signature))
        # Convert the json string into a dict if found.
        user_data = loads(data) if data else {}
        if user_data:
            raise DDBError("User already has an active session.", **user_data)

        # Loops once for each port we have available.
        for _ in range(self._range):
            # Lets db increment and return a value; this is multi-process-safe.
            offset = self._db.incr("COUNT")
            # Adjusts the offset to be within the range we have available.
            # For example, if the range is 10 and offset is 32, the check below should get the offset to be 2.
            if offset >= self._range:
                offset %= self._range
            # Use the offset and min_port to find the port we should use.
            port = offset + self._min_port
            # Check if the port is not marked as being active in the db.
            # If it is, return it. If it's not, loop to try a new port.
            port_key = self._port_key(port)
            if self._db.get(port_key) != self._port_active_token:
                return port

        # If the code gets here, none of the ports we tried was available per the db.
        raise DDBError("Could not find an available port")

    def store_user_info(self, *, user_signature: str, **kwargs) -> None:
        """Store session information for the given user and mark port as used."""
        assert "port" in kwargs, "You must store the active port for the user."
        # Create a db-key for the user.
        user_key = self._user_key(user_signature)
        # Check if this user already has an active session.
        # Retrieve data from db.
        data = self._db.get(user_key)
        # Convert the json string into a dict if found.
        user_data = loads(data) if data else {}
        if user_data:
            raise DDBError(
                "User already has an active session.",
                user_signature=user_signature,
                **user_data,
            )
        # Store user information as a json string.
        self._db.set(user_key, dumps(kwargs))

        # Create a port-key for this session.
        port_key = self._port_key(kwargs["port"])
        # Check if the port is already in use.
        if self._db.get(port_key) == self._port_active_token:
            raise DDBError(
                "Port is already in use.",
                user_signature=user_signature,
                **kwargs,
            )
        # If available, mark port as active.
        self._db.set(port_key, self._port_active_token)

    def get_user_info(self, *, user_signature: str) -> Dict:
        """Return session information for the given user."""
        # Retrieve data from db.
        data = self._db.get(self._user_key(user_signature))
        # Convert the json string into a dict if found.
        user_data = loads(data) if data else {}
        if user_data:
            return user_data
        raise DDBError(
            "Could not find an active session for user.", user_signature=user_signature
        )

    def delete_session(self, *, user_signature: str) -> bool:
        """Delete session information for the given user and mark port as available. Return True if an entry was found and removed."""
        user_key = self._user_key(user_signature)
        # Retrieve data from db.
        data = self._db.get(user_key)
        # Convert the json string into a dict if found.
        user_data = loads(data) if data else {}
        if user_data:
            port = user_data["port"]
            port_key = self._port_key(port)
            self._db.set(port_key, self._port_available_token)
            self._db.delete(user_key)
            return True
        # Did not find an entry for given user.
        return False


class DDBError(Exception):
    """Class to communicate session information if there are any errors."""

    def __init__(self, message, **kwargs):
        super().__init__(message)
        self.extra_info = kwargs
