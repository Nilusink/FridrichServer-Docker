from fridrich.classes import User
from fridrich.server import Const
from time import strftime


def ping(message: dict, user: User, *_args) -> None:
    """
    immediately send back a message (to measure latency)
    """
    user.send(message)


def get_time(_message: dict, user: User, *_args) -> None:
    """
    get the current server time
    """
    user.send({
            "now": strftime("%H:%M:%S"),
            "voting": Const.switchTime
        })


def get_sec_clearance(_message: dict, user: User, *_args):
    """
    send the user its security clearance
    """
    user.send(user.sec)
