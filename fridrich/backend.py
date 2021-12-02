"""
used to interface with a Fridrich Server
(Client)

Author: Nilusink
"""
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Dict, Callable, Iterable, Any
from contextlib import suppress
from traceback import format_exc
from fridrich import app_store
from hashlib import sha512
from fridrich import *
import socket
import struct
import json
import time


# for information if the Server has updated the communication but the client hasn't yet
COMM_PROTOCOL_VERSION = "1.1.0"


############################################################################
#                             other functions                              #
############################################################################
def json_repair(string: str) -> str:
    """
    if two messages are scrambled together, split them and use the first one
    """
    parts = string.split('}{')  # happens sometimes, probably because python is to slow
    if len(parts) > 1:
        return parts[0]+'}'
    return string


def date_for_sort(message) -> str:
    """
    go from format "hour:minute:second:millisecond - day.month.year" to "year.month.day - hour:minute:second:millisecond"
    """
    y = message['time'].split(' - ')    # split date and time
    return '.'.join(reversed(y[1].split('.')))+' - '+y[0]   # reverse date and place time at end


def debug(func: Callable) -> Callable:
    def wrapper(*args, **kw):
        try:
            return func(*args, **kw)

        except Exception:
            with open("backend.err.log", 'a') as out:
                out.write(format_exc())
            raise
    return wrapper


############################################################################
#                      Server Communication Class                          #
############################################################################
class Connection:
    def __init__(self, debug_mode: str | None = Off, host: str | None = 'fridrich') -> None:
        """
        connect with any fridrich server
        options:
            ``debug_mode`` - ``"normal"`` | ``"full"`` | ``False``

            ``host`` - name of the host, either IP or hostname / address
        """
        self._messages = dict()
        self._server_messages = dict()
        self.Server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create socket instance
        self.debug_mode = debug_mode

        self.__ServerIp = ""
        self.server_ip = host

        if self.debug_mode in ('normal', 'full'):
            print(ConsoleColors.OKGREEN + 'Server IP: ' + self.server_ip + ConsoleColors.ENDC)
        self.port = 12345   # set communication port with server

        self.AuthKey = None
        self._userN = None

        self.loop = True

        self.executor = ThreadPoolExecutor(max_workers=1)
        self.receive_thread = Future

        # for down-/uploading
        self.load_state = str()
        self.load_progress = float()
        self.load_program = str()

        # message pool
        self.__message_pool: list = []

    # properties
    @property
    def username(self) -> str:
        """
        get username
        """
        return self._userN

    @property
    def server_ip(self) -> str:
        return self.__ServerIp

    @server_ip.setter
    def server_ip(self, value: str) -> None:
        sl = value.split('.')
        if len(sl) == 4 and all([digit in '0123456789' for element in sl for digit in element]):
            if self.debug_mode in ("full", "normal"):
                try:
                    socket.gethostbyaddr(value)
                except socket.herror:
                    print(ConsoleColors.WARNING+f"Hostname of {value} not found, may be unreachable"+ConsoleColors.ENDC)
            self.__ServerIp = value
        else:
            self.__ServerIp = socket.gethostbyname(value)  # get ip of fridrich

        if self.debug_mode == 'full':
            print(self.server_ip)

    # "local" functions
    @staticmethod
    def error_handler(error: str, *args) -> None:
        """
        Handle incoming errors
        """
        match error:    # match errors where not specific error class exists (and NotEncryptedError)
            case 'NotVoted':
                raise NameError('No votes registered for user')

            case 'json':
                raise JsonError('Crippled message')

            case 'SecurityNotSet':
                raise SecurityClearanceNotSet(args[0]['info'])

            case 'NotEncryptedError':
                raise cryption_tools.NotEncryptedError('Server received non encrypted message')

            case _:  # for all other errors try to raise them and when that fails, raise a ServerError
                if 'full' in args[0] and 'info' in args[0]:
                    st = f'raise {error}("info: {args[0]["info"]} -- Full Traceback: {args[0]["full"]}")'

                elif 'info' in args[0]:
                    st = f'raise {error}("info: {args[0]["info"]}")'

                else:
                    st = f'raise {error}'

                try:
                    exec(st)

                except NameError:
                    raise ServerError(f'{error}:\n{st.lstrip(f"raise {error}(").rstrip(")")}')

    @staticmethod
    def response_handler(responses: Dict[str, Any]) -> Dict[str, Any]:
        """
        if necessary, process each result
        """
        for response in responses.keys():
            match response:
                case "secReq":
                    responses["seqReq"] = responses[response]['sec']

                case "gRes":
                    res = responses[response]
                    out = dict()

                    for voting in res:
                        attendants = dict()  # create dictionary with all attendants: votes
                        nowVoting = res[voting]
                        print(nowVoting)
                        for element in [nowVoting[element] for element in nowVoting] + (['Lukas', 'Niclas', 'Melvin'] if voting == 'GayKing' else []):
                            attendants[element] = 0

                        votes = int()
                        for element in res[voting]:  # assign votes to attendant
                            votes += 1
                            attendants[res[voting][element]] += 1
                        out[voting] = dict()
                        out[voting]['totalVotes'] = votes
                        out[voting]['results'] = attendants

                    responses["gRes"] = out

                case "getFrees":
                    responses["getFrees"] = responses["getFrees"]['Value']

                case "getChat":
                    raw = responses["getChat"]
                    responses["getChat"] = sorted(raw, key=date_for_sort)

                case "get_var":
                    responses["get_var"] = responses["get_var"]["var"]

                case "ping":
                    responses["ping"] = (time.time() - responses["ping"]["time"]) * 1000

        return responses

    def _send(self, dictionary: dict, wait: bool | None = False) -> float | None:
        """
        send messages to server
        :param dictionary: dict to send
        :param wait: don't send the messages immediately and wait
        :return: time of sending
        """
        self.__message_pool.append(dictionary)

        if not wait:
            return self.__send()

    def __send(self) -> float:
        if not self.__nonzero__():
            raise AuthError("Not authenticated")

        for element in self.__message_pool:
            if "message" in element:
                element["message"] = element["message"].replace("'", "\'").replace('"', '\"')

        message = {
            "time": time.time(),
            "content": self.__message_pool
        }

        # reset message pool
        self.__message_pool = []

        if self.AuthKey:
            stringMes = json.dumps(message, ensure_ascii=True)
            mes = cryption_tools.MesCryp.encrypt(stringMes, key=self.AuthKey.encode())
            self.Server.send(mes)
            if self.debug_mode in ('normal', 'full'):
                print(ConsoleColors.OKCYAN+stringMes+ConsoleColors.ENDC)
            if self.debug_mode == 'full':
                print(ConsoleColors.WARNING+str(mes)+ConsoleColors.ENDC)

            return message["time"]

        stringMes = json.dumps(message, ensure_ascii=False)
        self.Server.send(cryption_tools.MesCryp.encrypt(stringMes))
        if self.debug_mode in ('normal', 'full'):
            print(ConsoleColors.OKCYAN+stringMes+ConsoleColors.ENDC)

        return message["time"]

    def send(self) -> Any:
        """
        send the messages and also receive them
        """
        return self.wait_for_message(self.__send())

    @debug
    def receive(self):
        """
        receive messages from server, decrypt them and raise incoming errors
        """
        while self.loop:
            try:
                bs = self.Server.recv(8)    # receive message length
                (length,) = struct.unpack('>Q', bs)

            except (ConnectionResetError, struct.error):
                continue

            data = b''
            no_rec = 0
            to_read = 0
            while len(data) < length:   # receive message in patches so size doesn't matter
                o_to_read = to_read
                to_read = length - len(data)
                data += self.Server.recv(
                                    4096 if to_read > 4096 else to_read
                                    )

                if to_read == o_to_read:    # check if new packages were received
                    no_rec += 1
                else:
                    no_rec = 0

                if no_rec >= 100:          # if for 100 loops no packages were received, raise connection loss
                    raise socket.error('Failed receiving data - connection loss')

            try:
                mes = cryption_tools.MesCryp.decrypt(data, self.AuthKey.encode())
            except cryption_tools.InvalidToken:
                self._messages["Error"] = f"cant decrypt: {data}"
                continue

            try:
                for _ in range(2):
                    mes = mes.replace("\\\\", "\\")
                mes = json.loads(mes)
                print(f"received message: {mes=}")

            except json.decoder.JSONDecodeError:
                self._messages["Error"] = f"cant decode: {mes}, type: {type(mes)}"
                continue

            try:
                # parse each message
                for resp_type, message in mes["content"].items():
                    match message["type"]:
                        case "function":
                            if mes["time"] not in self._messages:
                                self._messages[mes["time"]] = {}

                            self._messages[mes["time"]][resp_type] = message["content"]

                        case "Error":
                            self._messages["Error"] = f"{message['Error']} - {message['info']}"

                        case "disconnect":
                            self._messages["disconnect"] = True
                            self.end()

                        case "ServerRequest":
                            self._server_messages[mes['time']] = message

                        case _:
                            raise ServerError(f"server send message: {mes}")

            except KeyError:
                with open("backend.err.log", 'a') as out:
                    out.write(format_exc()+f'message: {mes}')
                raise

    def wait_for_message(self, time_sent: float, timeout: int | bool | None = 10, delay: int | None = .1) -> dict:
        """
        wait for the server message to be received.
        :param time_sent: the time the message was sent
        :param timeout: raise a error if no correct message was received (seconds)
        :param delay: The delay for the while loop when checking self.messages
        :return: message(dict)
        """
        start = time.time()
        if self.debug_mode in ('full', 'normal'):
            print(f'waiting for message: {time_sent}')
        while time_sent not in self._messages:  # wait for server message
            if self.debug_mode == 'full':
                print(self._messages)
            if timeout and time.time()-start >= timeout:
                raise NetworkError("no message was received from server before timeout")
            if "Error" in self._messages:
                raise Error(self._messages["Error"])
            if "disconnect" in self._messages:
                raise ConnectionAbortedError("Server ended connection")
            time.sleep(delay)

        out = self._messages[time_sent]
        del self._messages[time_sent]
        if "Error" in out:
            self.error_handler(out["Error"], out)
        if self.debug_mode in ('all', 'normal'):
            print(f"found message: {out}")

        out = self.response_handler(out)

        return out

    def reconnect(self) -> None:
        """
        reconnect to server
        """
        try:    # try to reconnect to the server
            self.Server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.Server.connect((self.server_ip, self.port))  # connect to server
        except socket.error:
            raise ConnectionError('Server not reachable')

    # user functions
    def auth(self, username: str, password: str) -> bool:
        """
        authenticate with the server
        """
        if not self.loop:
            raise Error("already called 'end'")
        self.reconnect()
        msg = {  # message
            'type': 'auth',
            'Name': username,
            'pwd': sha512(password.encode()).hexdigest(),
            "com_protocol_version": COMM_PROTOCOL_VERSION
        }
        self._userN = username
        self.AuthKey = None  # reset AuthKey
        stringMes = json.dumps(msg, ensure_ascii=False)

        mes = cryption_tools.MesCryp.encrypt(stringMes)
        self.Server.send(mes)

        mes = json.loads(cryption_tools.MesCryp.decrypt(self.Server.recv(2048)))
        if "Error" in mes:
            self.error_handler(mes["Error"], mes)
        self.AuthKey = mes['AuthKey']

        self.receive_thread = self.executor.submit(self.receive)  # start thread for receiving
        return mes['Auth']  # return True or False

    def get_sec_clearance(self, wait: bool | None = False) -> str | None:
        """
        if signed in, get security clearance
        """
        msg = {'type': 'secReq'}
        self._send(msg)

        t = self._send(msg, wait=wait)
        if not wait:
            return self.wait_for_message(t)["secReq"]

    def send_vote(self, *args, flag: str | None = 'vote', voting: str | None = 'GayKing', wait: bool | None = False) -> None:
        """
        send vote to server\n
        flag can be "vote", "unvote", "dvote" or "dUvote", voting is custom\n
        DoubleVotes are only available once a week\n
        types will be ignored if flag is "dvote"
        """
        msg = {
               'type': flag,
               'voting': voting
        }
        if flag in ('vote', 'dvote'):
            msg['vote'] = args[0]  # if vote send vote

        t = self._send(msg, wait=wait)  # send vote and receive success or error
        if not wait:
            self.wait_for_message(t)

    def get_results(self, flag: str | None = 'now', wait: bool | None = False) -> dict | None:
        """
        get results of voting\n
        flag can be "now", "last"\n
        return format: {voting : {"totalvotes" : int, "results" : {name1 : votes, name2 : votes}}}
        """
        msg = {
               'type': 'gRes',
               'flag': flag
        }    # set message
        t = self._send(msg, wait=wait)    # send message and get response
        if not wait:
            return self.wait_for_message(t)["gRes"]

    def get_log(self, wait: bool | None = False) -> dict | None:
        """
        get list of recent GayKings
        """
        msg = {
               'type': 'gLog'
        }   # set message
        t = self._send(msg, wait=wait)    # send request and get response
        if not wait:
            return self.wait_for_message(t)["gLog"]

    @staticmethod
    def calculate_streak(log: dict) -> tuple[str, int]:
        """
        if someone got voted multiple times in a row,\n
        return his/her/their name and how often they\n
        got voted\n
        return format: (Name, Streak)
        """
        sorted_log = {x: log[x] for x in sorted(log, key=lambda x: '.'.join(reversed(x.split('.'))))}    # sort list by year, month, date

        fullList = list(reversed(list(useful.Dict.values(sorted_log))))  # get list of all Kings
        StreakGuys = list(fullList[0].split('|'))   # if a|b|c make list of (a, b, c), else just (a)

        StreakDict = {StreakGuy: int() for StreakGuy in StreakGuys}  # create Dictionary with scheme: {a:0, b:0, c:0}
        for StreakGuy in StreakGuys:    # iterate all guys
            for element in fullList:    # iterate all votes
                if StreakGuy.lower() in element.lower():    # guy was in previous vote
                    StreakDict[StreakGuy] += 1    # add to streak and continue
                else:
                    break   # else begin with new guy

        iDict = useful.Dict.inverse(StreakDict)    # inverse Dict ({1:a, 3:b, 0:c} instead of {a:1, b:3, c:0})
        max_num = max(list(iDict))
        Name = '|'.join([name for name in StreakDict if StreakDict[name] == max_num])

        return Name, max_num  # return results

    def get_temps(self, wait: bool | None = False) -> Dict[str, dict] | None:
        """
        get room and cpu temperature in °C as well as humidity in %
        """
        msg = {'type': 'get_temps'}  # set message
        t = self._send(msg, wait=wait)    # send message and get response
        if not wait:
            return self.wait_for_message(t)["get_temps"]

    def get_cal(self, wait: bool | None = False) -> dict | None:
        """
        get Calendar in format {"date":listOfEvents}
        """
        msg = {
               'type': 'calReq'
        }   # set message
        t = self._send(msg, wait=wait)    # send message and get response
        if not wait:
            return self.wait_for_message(t)["calReq"]

    def send_cal(self, date: str, event: str, wait: bool | None = False) -> None:
        """
        send entry to calender
        """
        msg = {
               'type': 'CalEntry',
               'date': date,
               'event': event
        }   # set message
        self._send(msg, wait=wait)  # send request and receive response (success, error)

    def change_pwd(self, new_password: str, wait: bool | None = False) -> None:
        """
        Change password of user currently logged in to
        """
        msg = {
               'type': 'changePwd',
               'newPwd': sha512(new_password.encode()).hexdigest()
        }    # set message
        self._send(msg, wait=wait)  # send request and get response (success, error)

    def get_vote(self, flag: str | None = 'normal', voting: str | None = 'GayKing', wait: bool | None = False) -> str | None:
        """
        get current vote of user\n
        flag can be normal or double
        """
        msg = {
               'type': 'getVote',
               'flag': flag,
               'voting': voting
        }    # set message
        t = self._send(msg, wait=wait)    # send message and get response
        if not wait:
            return self.wait_for_message(t)["getVote"]

    def get_version(self, wait: bool | None = False) -> str | None:
        """
        get current version of GUI program
        """
        msg = {
               'type': 'getVersion'
        }  # set message
        t = self._send(msg, wait=wait)  # send message and get response
        if not wait:
            return self.wait_for_message(t)["getVersion"]

    def set_version(self, version: str, wait: bool | None = False) -> None:
        """
        set current version of GUI program
        """
        msg = {
               'type': 'setVersion',
               'version': version
        }
        self._send(msg, wait=wait)  # send request and get response (success, error)

    def get_frees(self, wait: bool | None = False) -> int | None:
        """
        get free double votes
        """
        msg = {
               'type': 'getFrees'
        }
        t = self._send(msg, wait=wait)  # send message and get response
        if not wait:
            return self.wait_for_message(t)["getFrees"]

    def get_online_users(self, wait: bool | None = False) -> list | None:
        """
        get list of currently online users
        """
        msg = {
               'type': 'gOuser'
        }
        t = self._send(msg, wait=wait)  # send message and get response
        if not wait:
            return self.wait_for_message(t)["gOuser"]

    def send_chat(self, message: str, wait: bool | None = False) -> None:
        """
        send message to chat
        """
        msg = {
               'type': 'appendChat',
               'message': message
        }
        self._send(msg, wait=wait)  # send request and get response (success, error)

    def get_chat(self, wait: bool | None = False) -> list | None:
        """
        get list of all chat messages
        """
        msg = {
               'type': 'getChat'
        }
        t = self._send(msg, wait=wait)  # send message and get response
        if not wait:
            return self.wait_for_message(t)["getChat"]

    # user controlled variables:
    def get_all_vars(self, wait: bool | None = False) -> dict | None:
        """
        get all user controlled variables inside a dict
        """
        msg = {
            "type": "get_all_vars"
        }
        t = self._send(msg, wait=wait)  # send message and get response
        if not wait:
            return self.wait_for_message(t)["get_all_vars"]

    def get_var(self, variable: str, wait: bool | None = False) -> Any | None:
        """
        get a user controlled variable
        """
        msg = {
            "type": "get_var",
            "var": variable
        }
        t = self._send(msg, wait=wait)  # send message and get response
        if not wait:
            return self.wait_for_message(t)["get_var"]

    def set_var(self, variable: str, value, wait: bool | None = False) -> None:
        """
        set a user controlled variable
        must be json valid!
        """
        msg = {
            "type": "set_var",
            "var": variable,
            "value": value
        }
        try:
            t = self._send(msg, wait=wait)

        except TypeError:
            raise TypeError("variable not json valid!")

        if not wait:
            return self.wait_for_message(t)[0]

    def del_var(self, variable: str, wait: bool | None = False) -> None:
        """
        delete a user controlled variable
        """
        msg = {
            "type": "del_var",
            "var": variable
        }
        t = self._send(msg, wait=wait)  # send message and get response
        if not wait:
            return self.wait_for_message(t)[0]

    def __iter__(self) -> Iterable:
        """
        return dict of all User Controlled Variables when called
        """
        _d = self.get_all_vars()
        for element in _d:
            yield element, _d[element]

    def __getitem__(self, item: str):
        return self.get_var(item)

    def __setitem__(self, key: str, value) -> None:
        return self.set_var(key, value)

    def __delitem__(self, item: str) -> None:
        return self.del_var(item)

    # Admin Functions
    def admin_get_users(self, wait: bool | None = False) -> list | None:
        """
        get list of all users with passwords and security clearance\n
        return format: [{"Name":username, "pwd":password, "sec":clearance}, ...]
        """
        msg = {
               'type': 'getUsers'
        }
        self._send(msg)
        t = self._send(msg, wait=wait)  # send message and get response
        if not wait:
            return self.wait_for_message(t)["getUsers"]

    def admin_set_password(self, user: str, password: str, wait: bool | None = False) -> None:
        """
        set password of given user
        """
        msg = {
               'type': 'setPwd',
               'User': user,
               'newPwd': sha512(password.encode()).hexdigest()
        }
        self._send(msg, wait=wait)  # send request and get response (success, error)

    def admin_set_username(self, old_username: str, new_username: str, wait: bool | None = False) -> None:
        """
        change username of given user
        """
        msg = {
               'type': 'setName',
               'OldUser': old_username,
               'NewUser': new_username
        }
        self._send(msg, wait=wait)  # send request and get response (success, error)

    def admin_set_security(self, username: str, password: str, wait: bool | None = False) -> None:
        """
        change security clearance of given user
        """
        msg = {
               'type': 'setSec',
               'Name': username,
               'sec': password
        }
        self._send(msg, wait=wait)  # send request and get response (success, error)

    def admin_add_user(self, username: str, password: str, clearance: str, wait: bool | None = False) -> None:
        """
        add new user
        """
        msg = {
               'type': 'newUser',
               'Name': username,
               'pwd': sha512(password.encode()).hexdigest(),
               'sec': clearance
        }
        self._send(msg, wait=wait)  # send request and get response (success, error)

    def admin_remove_user(self, username: str, wait: bool | None = False) -> None:
        """
        remove user
        """
        msg = {
               'type': 'removeUser',
               'Name': username
        }
        self._send(msg)
        self._send(msg, wait=wait)  # send request and get response (success, error)

    def admin_reset_logins(self, wait: bool | None = False) -> None:
        """
        reset all current logins
        """
        msg = {
               'type': 'rsLogins'
        }
        self._send(msg, wait=wait)  # send request and get response (success, error)

    def manual_voting(self, wait: bool | None = False) -> None:
        """
        trigger a voting manually
        """
        msg = {
            "type": "trigger_voting"
        }
        self._send(msg, wait=wait)  # send request and get response (success, error)

    # AppStore functions
    def get_apps(self, wait: bool | None = False) -> list:
        """
        get all available apps and versions
        """
        msg = {
            "type": "get_apps"
        }
        t = self._send(msg, wait=wait)  # send message and get response
        if not wait:
            return self.wait_for_message(t)["get_apps"]

    def download_app(self, app: str, directory: str | None = ...) -> None:
        """
        :param app: which app to download
        :param directory: where the program should be downloaded to
        """
        msg = {
            "type": "download_app",
            "app": app
        }
        meta = self.wait_for_message(self._send(msg, wait=False))["download_app"]

        self.load_state = "Uploading"
        for _ in meta:
            thread = app_store.send_receive(mode='receive', print_steps=False, download_directory=directory, thread=True, overwrite=True)
            while thread.running():
                self.load_program = app_store.download_program
                self.load_progress = app_store.download_progress
        self.load_state = str()
        self.load_program = str()
        self.load_progress = float()

    def _send_app(self, files: list | tuple, app_name: str) -> None:
        for file in files:
            thread = app_store.send_receive(mode="send", filename=file, destination=self.server_ip, print_steps=False, thread=True, overwrite=True)
            while thread.running():
                self.load_program = app_name
        self.load_program = str()
        self.load_state = str()

    def create_app(self, app_name: str, app_version: str, app_info: str, files: list | tuple) -> None:
        """
        add a new app to the fridrich appstore
        """
        msg = {
            "type": "create_app",
            "name": app_name,
            "version": app_version,
            "info": app_info,
            "files": [file.split("/")[-1] for file in files]
        }
        self.wait_for_message(self._send(msg, wait=False))
        self.load_state = "Uploading"
        self._send_app(files, app_name)

    def modify_app(self, old_app_name: str, app_name: str, app_version: str, app_info: str, files: list | tuple, to_delete: list | tuple) -> None:
        """
        configure an already existing app

        :param old_app_name: the original name of the app
        :param app_name: the name of the app
        :param app_version: the version of the app
        :param app_info: the info of the app
        :param files: a list with files to update (full path, overwriting old files)
        :param to_delete: a list with App-Files that should be deleted (if the exist!)
        """
        msg = {
            "type": "modify_app",
            "o_name": old_app_name,
            "name": app_name,
            "version": app_version,
            "info": app_info,
            "files": [file.split("/")[-1].split("\\")[-1] for file in files],
            "to_remove": to_delete
        }
        self.wait_for_message(self._send(msg, wait=False))
        self._send_app(files, app_name)

    # tools
    def ping(self, wait: bool | None = False) -> float:
        """
        ping the server to check the connection time
        :return: time in ms
        """
        msg = {
            "type": "ping",
            "time": time.time()
        }
        t = self._send(msg, wait=wait)  # send message and get response
        if not wait:
            return self.wait_for_message(t)["ping"]

    def get_server_time(self, wait: bool | None = False) -> dict:
        """
        get the current server time and voting time
        """
        msg = {
            "type": "get_time"
        }
        t = self._send(msg, wait=wait)  # send message and get response
        if not wait:
            return self.wait_for_message(t)["get_time"]

    # magical functions
    def __repr__(self) -> str:
        return f'Backend instance (debug_mode: {self.debug_mode}, user: {self._userN}, authkey: {self.AuthKey})'

    def __str__(self) -> str:
        """
        return string of information when str() is called
        """
        return self.__repr__()

    def __nonzero__(self) -> bool:
        """
        return True if AuthKey
        """
        return bool(self.AuthKey)

    def __bool__(self) -> bool:
        """
        return True if AuthKey
        """
        return self.__nonzero__()

    # the end
    def end(self, revive: bool | None = False) -> None:
        """
        close connection with server and logout
        """
        msg = {
               'type': 'end'
        }    # set message
        with suppress(ConnectionResetError, ConnectionAbortedError):
            self._send(msg, wait=False)  # send message
        app_store.executor.shutdown(wait=False)
        self.AuthKey = None
        self._userN = None
        self.executor.shutdown(wait=False)
        self.loop = False

        if revive:
            self.executor = ThreadPoolExecutor(max_workers=1)
            app_store.executor = ThreadPoolExecutor()
            self.loop = True
