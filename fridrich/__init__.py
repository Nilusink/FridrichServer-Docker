"""
The fridrich module is a set of scripts used
to drive a Server, which is used mainly for
the GayVoting (There is much more to this,
but it's not really easy to explain),
and a Client that connects to the Server

Author: Nilusink
"""
from fridrich import cryption_tools
from fridrich import useful


class ConsoleColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# error classes
class ServerError(Exception):
    pass


class AccessError(Exception):
    pass


class AuthError(Exception):
    pass


class JsonError(Exception):
    pass


class NoVotes(Exception):
    pass


class UnknownError(Exception):
    pass


class RegistryError(Exception):
    pass


class NotAUser(Exception):
    pass


class InvalidRequest(Exception):
    pass


class SecurityClearanceNotSet(Exception):
    pass


class MessageError(Exception):
    pass


class InvalidStringError(Exception):
    pass


class NetworkError(Exception):
    pass


class Error(Exception):
    pass


Off = False
On = True
true = False
false = True
