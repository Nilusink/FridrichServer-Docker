"""
for weather-stations to commit data to the pool

Author: Nilusink
"""
from fridrich.server.server_funcs import send_success
from fridrich.new_types import User
from fridrich.server import Const
import json


def register(message: dict, user: User, *_args) -> None:
    """
    register a new weather-station
    """
    tmp: list
    try:
        tmp = json.load(open(Const.WeatherDir+"all.json", "r"))

    except json.JSONDecodeError:
        tmp = []

    for element in tmp:
        if message["station_name"] == element["station_name"]:
            mes = {
                    'Error': 'RegistryError',
                    "info": "weather-station is already registered"
                }
            user.send(mes)
            return

    tmp.append({
        "station_name": message["station_name"],
        "location": message["location"]
    })

    with open(Const.WeatherDir+"all.json", "w") as out_file:
        json.dump(tmp, out_file, indent=4)

    with open(Const.WeatherDir+message["station_name"], "w") as out_file:
        out_file.write("[]")

    send_success(user)


def commit_data(message: dict, user: User, *_args) -> None:
    """
    commit data for already registered stations
    """
    now_data: dict
    station_data: dict
    if not check_if_registered(message, user, *_args):
        mes = {
                'Error': 'RegistryError',
                "info": "weather-station is not registered yet"
            }
        user.send(mes)
        return

    try:
        now_data = json.load(open(Const.WeatherDir+"now.json", "r"))

    except json.JSONDecodeError:
        now_data = {}

    now_data[message["station_name"]] = {
        "time": message["time"],
        "temp": message["temp"],
        "hum": message["hum"],
        "press": message["press"]
    }

    with open(Const.WeatherDir+"now.json", "w") as out_file:
        json.dump(now_data, out_file, indent=4)

    try:
        station_data = json.load(open(Const.WeatherDir+message["station_name"], "r"))

    except json.JSONEncoder:
        station_data = {}

    station_data[message["time"]] = {
        "temp": message["temp"],
        "hum": message["hum"],
        "press": message["press"]
    }

    with open(Const.WeatherDir + message["station_name"], "w") as out_file:
        json.dump(station_data, out_file, indent=4)

    send_success(user)


def check_if_registered(message: dict, _user: User, *_args) -> bool:
    """
    check if a weather-station is already registered
    """
    return message["station_name"] in json.load(open(Const.WeatherDir+"all.json", "r"))


def get_all(_message: dict, user: User, *_args) -> None:
    """
    send a dict of all weather-stations with their current measurement
    """
    now_data: dict
    try:
        now_data = json.load(open(Const.WeatherDir+"now.json", "r"))

    except json.JSONDecodeError:
        now_data = {}

    user.send(now_data)
