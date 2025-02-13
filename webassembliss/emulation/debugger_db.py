from json import dumps, loads
from os import environ
from typing import Dict, Optional, Union

from redis import Redis


class DebuggerDB:
    """Class to manage the ports we can use for concurrent debugging sessions."""

    def __init__(
        self,
        *,
        host: str = environ.get("REDIS_HOST", "localhost"),
        port: int = int(environ.get("REDIS_PORT", "6379")),
        password: str = environ.get("REDIS_PASSWORD", ""),
        min_port: int = 9_999,
        max_port: int = 10_999,
        user_prefix: str = "USER_",
        port_prefix: str = "PORT_",
        init_session_count: int = 0,
        port_active_token: str = "ACTIVE",
        port_available_token: str = "free",
        stdout_prefix: str = "STDOUT_",
        stderr_prefix: str = "STDERR_",
        exit_code_prefix: str = "EXIT_",
        insr_count_prefix: str = "INSTR_COUNT_",
    ):
        # Create a connection with the db that decodes responses automatically.
        self._db = Redis(host=host, port=port, password=password, decode_responses=True)
        # Initialize the required values in the database if they're not there.
        self._db.setnx("VAR_MIN_PORT", min_port)
        self._db.setnx("VAR_MAX_PORT", max_port)
        self._db.setnx("VAR_USER_PREFIX", user_prefix)
        self._db.setnx("VAR_PORT_PREFIX", port_prefix)
        self._db.setnx("VAR_PORT_ACTIVE_TOKEN", port_active_token)
        self._db.setnx("VAR_PORT_AVAILABLE_TOKEN", port_available_token)
        self._db.setnx("VAR_STDOUT_PREFIX", stdout_prefix)
        self._db.setnx("VAR_STDERR_PREFIX", stderr_prefix)
        self._db.setnx("VAR_EXITCODE_PREFIX", exit_code_prefix)
        self._db.setnx("VAR_INSTRCOUNT_PREFIX", insr_count_prefix)
        # Load the required values from the db, in case another client had overwritten them.
        # These values should not change during execution, so it's fine to have a local copy.
        self._min_port: int = int(self._db.get("VAR_MIN_PORT"))  # type: ignore[arg-type]
        self._max_port: int = int(self._db.get("VAR_MAX_PORT"))  # type: ignore[arg-type]
        self._user_prefix: str = self._db.get("VAR_USER_PREFIX")  # type: ignore[assignment]
        self._port_prefix: str = self._db.get("VAR_PORT_PREFIX")  # type: ignore[assignment]
        self._port_active_token = self._db.get("VAR_PORT_ACTIVE_TOKEN")  # type: ignore[assignment]
        self._port_available_token = self._db.get("VAR_PORT_AVAILABLE_TOKEN")  # type: ignore[assignment]
        self._stdout_prefix: str = self._db.get("VAR_STDOUT_PREFIX")  # type: ignore[assignment]
        self._stderr_prefix: str = self._db.get("VAR_STDERR_PREFIX")  # type: ignore[assignment]
        self._exitcode_prefix: str = self._db.get("VAR_EXITCODE_PREFIX")  # type: ignore[assignment]
        self._insr_count_prefix: str = self._db.get("VAR_INSTRCOUNT_PREFIX")  # type: ignore[assignment]
        # Store the number of ports that we can use.
        self._range: int = self._max_port - self._min_port + 1
        # If received a non-zero session count, initialize it if it's not set yet.
        if init_session_count:
            # This is mostly here for webapp-debugging purposes.
            # This value is volatile, so we should not have a copy away from the db.
            self._db.setnx("SESSION_COUNT", init_session_count)

    def _user_key(self, user_signature: str) -> str:
        """Create a db-key for user data in a standard manner."""
        return f"{self._user_prefix}{user_signature}"

    def _port_key(self, port: int) -> str:
        """Create a port-key for port data in a standard manner."""
        return f"{self._port_prefix}{port:_}"

    def _output_key(self, port: int, output_type: str) -> str:
        """Create an output-key for output information in a standard manner."""
        if output_type == "stdout":
            return f"{self._stdout_prefix}{port:_}"
        elif output_type == "stderr":
            return f"{self._stderr_prefix}{port:_}"
        raise DDBError(
            f"Unknown output type '{output_type}'; expected 'stdout' or 'stderr'.",
            port=port,
            output_type=output_type,
        )

    def _exit_code_key(self, port: int) -> str:
        """Create an exitcode-key for sysexit information in a standard manner."""
        return f"{self._exitcode_prefix}{port:_}"

    def _instr_count_key(self, port: int) -> str:
        """Create an instrcount-key for gdb command information in a standard manner."""
        return f"{self._insr_count_prefix}{port:_}"

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
            offset = self._db.incr("SESSION_COUNT")
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

    def store_new_session_info(self, *, user_signature: str, **kwargs) -> None:
        """Store new session information for the given user and mark port as used."""
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
        self._db.set(port_key, self._port_active_token)  # type: ignore[arg-type]

    def update_session_info(self, *, user_signature: str, **kwargs) -> None:
        """Update existing session information for the given user."""
        # Create a db-key for the user.
        user_key = self._user_key(user_signature)
        # Check if this user already has an active session.
        # Retrieve data from db.
        data = self._db.get(user_key)
        # Convert the json string into a dict if found.
        user_data = loads(data) if data else {}
        # If no session for the user, raise an error.
        if not user_data:
            raise DDBError(
                "User has no active session.",
                user_signature=user_signature,
                **kwargs,
            )
        # Updates the new values given.
        user_data.update(kwargs)
        # Store updated user information into the db.
        self._db.set(user_key, dumps(kwargs))

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
            if self._port_available_token:
                self._db.set(port_key, self._port_available_token)
            else:
                self._db.delete(port_key)
            self._db.delete(user_key)
            self._db.delete(self._output_key(port=port, output_type="stdout"))
            self._db.delete(self._output_key(port=port, output_type="stderr"))
            self._db.delete(self._exit_code_key(port))
            self._db.delete(self._instr_count_key(port))
            return True
        # Did not find an entry for given user.
        return False

    def write_output(self, *, port: int, output_type: str, content: str) -> int:
        """Store given output into the db."""
        out_key = self._output_key(port, output_type)
        value = self._db.get(out_key)
        value = (value + content) if value else content
        self._db.set(out_key, value)
        return len(value)

    def get_output(self, *, port: int, output_type: str) -> str:
        """Retrieve program output from the db."""
        out_key = self._output_key(port, output_type)
        value = self._db.get(out_key)
        return value if value else ""

    def set_exit_code(self, *, port: int, exit_code: Optional[Union[str, int]]) -> None:
        """Store program exit code into the db."""
        if exit_code is None:
            exit_code = ""
        self._db.set(self._exit_code_key(port), exit_code)

    def get_exit_code(self, *, port: int) -> str:
        """Retrieve program exit code from the db."""
        value = self._db.get(self._exit_code_key(port))
        return value if value is not None else ""

    def incr_instr_count(self, *, port: int) -> None:
        """Increase the number of executed qiling-gdb-instructions in the db."""
        self._db.incr(self._instr_count_key(port))

    def get_instr_count(self, *, port: int) -> int:
        """Retrieve the count of qiling-gdb-instructions executed from the db."""
        value = self._db.get(self._instr_count_key(port))
        return int(value) if value else 0


class DDBError(Exception):
    """Class to communicate session information if there are any errors."""

    def __init__(self, message, **kwargs):
        super().__init__(message)
        self.extra_info = kwargs
