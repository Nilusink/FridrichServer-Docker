from fridrich.server.server_funcs import send_success
from fridrich.new_types import User
from fridrich.server import Const
from time import strftime


def ping(_message: dict, user: User, *_args) -> None:
    """
    immediately send back a message (to measure latency)
    """
    send_success(user)


def get_time(_message: dict, user: User, *_args) -> None:
    """
    get the current server time
    """
    user.send({
            "now": strftime("%H:%M:%S"),
            "voting": Const.switchTime
        })
