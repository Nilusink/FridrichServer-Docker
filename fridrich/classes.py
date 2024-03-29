"""
defines new types for Users, FileVar, ...
(Server)

Author: Nilusink
"""
from concurrent.futures import ThreadPoolExecutor
from fridrich import cryption_tools
from struct import pack
import contextlib
import socket
import typing
import json
import time


class FileVar:
    def __init__(self, value: str | dict, files: str | list | tuple) -> None:
        """
        create a variable synced to one or more files
        """
        # filter all items that are not a string
        self.files = [file if type(file) == str else ... for file in files] if type(files) in (list, tuple) else [files]
        # remove all non standard items
        while ... in self.files:
            self.files.remove(...)

        self.value = value
        self.type = type(value)
        
        self.set(value)  # assign variable

    def __repr__(self) -> str:
        self.get()
        return repr(self.value)

    def __len__(self) -> int:
        """
        return the length of ``self.value``
        """
        self.get()
        return len(self.value)

    def __str__(self) -> str:
        """
        return string of ``self.value``
        """
        self.get()
        return str(self.value)

    # str options
    def __add__(self, other: str) -> str:
        self.get()
        self.check_type(str)

        self.set(self.value+other)

        return self.value

    # dict options
    def __getitem__(self, key: str) -> typing.Any:
        """get an item if ``self.value`` is a dict
        """
        self.get()  # update variable in case something in the file has changed
        self.check_type(dict)
        if key not in self.value:
            raise KeyError(f'"{key}" not in dict "{self.value}"')
        return self.value[key]

    def __setitem__(self, key, value) -> dict:
        """
        set an item of a dict
        """
        self.get()
        self.check_type(dict)
        self.value[key] = value
        self.set(self.value)
        return self.value

    def __delitem__(self, key: str) -> None:
        self.get()
        self.check_type(dict)

        del self.value[key]

    def __iter__(self) -> typing.Iterator:
        self.get()
        self.check_type(dict)

        for key, item in self.value.items():
            yield key, item

    # general options
    def __eq__(self, other) -> bool:
        """
        check if the ``==`` given value is the same as either the whole class or the value
        """
        self.get()
        if type(other) == FileVar:
            return other.value == self.value and list(other.files) == list(self.files)

        return other == self.value

    def __contains__(self, other) -> bool:
        self.get()
        return other in self.value

    def set(self, value: str | dict) -> None:
        """
        set the variable (update files)
        """
        self.value = value
        self.type = type(value)

        for file in self.files:
            for _ in range(5):  # check five times if a file is already opened, if failed then pass
                try:
                    with open(file, 'w') as out:
                        if self.type == dict:
                            json.dump(self.value, out, indent=4)
                            break
                        out.write(self.value)
                        break

                except IOError:
                    time.sleep(.2)

                except json.JSONDecodeError:
                    with open(file, "w") as out_p:
                        json.dump({}, out_p)

            else:
                raise IOError(f"Can't access file {file}")

    def get(self) -> str | dict:
        """
        get the variable in its original type
        """
        file = self.files[0]
        for _ in range(5):
            try:
                with open(file, 'r') as inp:
                    try:
                        self.value = json.load(inp)

                    except json.JSONDecodeError:
                        self.value = inp.read()

                self.type = type(self.value)

                return self.value

            except IOError:
                time.sleep(.2)

            except json.JSONDecodeError:
                with open(file, "w") as out_p:
                    json.dump({}, out_p)

        else:
            raise IOError(f"Can't access file {file}")

    def check_type(self, wanted_type: typing.Type[str] | typing.Type[dict]) -> None:
        """
        if type is wrong, raise an error
        """
        if not self.type == wanted_type:
            raise TypeError(f'Expected {wanted_type}, got {self.type}. This function is not available for the given variable type')


class User:
    def __init__(self, name: str, sec: str, key: str, user_id: int, cl: socket.socket, ip: str, function_manager: typing.Callable, debugger) -> None:
        """
        :param name: Name of the client
        :param sec: security clearance
        :param key: encryption key of client
        :param cl: the users socket instance
        :param ip: the users host ip
        :param function_manager: the manager class for executing functions
        :param debugger: a instance of server_funcs.Debug
        """
        self.__name = name
        self.__sec = sec
        self.__key = key
        self.__id = user_id

        self.__client = cl
        self.__ip = ip
        self.manager = function_manager
        self.debugger = debugger

        self.disconnect = False

        self.loop = True

        # message pool
        self.__message_pool_names: typing.Tuple[str, str] = ("", "")
        self.__message_pool: typing.Dict[str, typing.Any] = {}
        self.__message_pool_index: int = 0
        self.__message_pool_max: int = 0
        self.__message_pool_time: str = ""

    @property
    def name(self) -> str:
        """
        :return: the username of the user
        """
        return self.__name

    @property
    def sec(self) -> str:
        """
        :return: the security clearance of the user
        """
        return self.__sec

    @property
    def ip(self) -> str:
        """
        :return: the users host-ip
        """
        return self.__ip

    @property
    def id(self) -> int:
        """
        :return: the users id
        """
        return self.__id

    def receive(self) -> None:
        """
        needs to be run in a thread, handles communication with client
        """
        while self.loop:
            try:
                mes = cryption_tools.MesCryp.decrypt(self.__client.recv(2048), self.__key.encode())

                mes = json.loads(mes)

                # create message pool for request
                self.__message_pool_names = tuple(func_name["f_name"] if "f_name" in func_name else func_name["type"] for func_name in mes["content"])
                self.__message_pool_max = len(mes["content"])
                self.__message_pool_time = mes["time"]
                self.__message_pool_index = 0

                if not mes or mes is None:
                    self.send({'Error': 'MessageError', 'info': 'Invalid Message/AuthKey'}, message_type="Error", force=True)
                    continue

                for message in mes["content"]:
                    self.exec_func(message)

            except cryption_tools.NotEncryptedError:
                print("not encrypted")
                self.send({'Error': 'NotEncryptedError'}, message_type="Error", force=True)
                return

    def send(self, message: iter, message_type: str | None = 'function', force: bool | None = False) -> None:
        """
        save the message(s) for sending
        """
        message = {
            "content": message
        }
        if self.__message_pool_max == sum([0 if element is None else 1 for element in self.__message_pool]) and not force:
            print(f"Pool error: {self.__message_pool=}, {self.__message_pool_names=}, {message=}")
            raise IndexError("trying to send message but no pool index is out of range")

        message['type'] = message_type

        try:
            self.__message_pool[self.__message_pool_names[self.__message_pool_index]] = message
            self.__message_pool_index += 1

        except IndexError:  # if used with "force", appends the message in case of a IndexError (if the pool hasn't been created or something)
            if force:
                self.__message_pool["forced"] = message
            else:
                raise

        if force or self.__message_pool_index == self.__message_pool_max:   # aka all functions are done
            self._send()

    def _send(self) -> None:
        """
        actually send the message
        """
        # process the message
        mes = {
            "content": self.__message_pool,
            "time": self.__message_pool_time
        }
        stringMes = json.dumps(mes)
        mes = cryption_tools.MesCryp.encrypt(stringMes, key=self.__key.encode())
        length = pack('>Q', len(mes))   # get message length

        # send to client
        self.__client.sendall(length)
        self.__client.sendall(mes)

        # reset message pool
        self.__message_pool = {}
        self.__message_pool_index = 0
        self.__message_pool_max = 0
        self.__message_pool_time = ""
        self.__message_pool_names = ()

    def exec_func(self, message: dict):
        """
        execute functions for the client
        """
        try:
            self.manager(message, self)

        except Exception as e:
            self.debugger.write_traceback(e, from_user=self.name)
            return

    def end(self) -> None:
        print(f"Disconnecting: {self}")
        self.disconnect = True
        self.loop = False
        self.__client.close()

    def __getitem__(self, item) -> str:
        return dict(self)[item]

    def __iter__(self) -> typing.Iterator:
        for key, item in (('key', self.__key), ('name', self.__name), ('sec', self.__sec)):
            yield key, item

    def __str__(self) -> str:
        return f"<class User (name={self.__name}, sec={self.__sec})>"

    def __repr__(self) -> str:
        return self.__str__()

    def __contains__(self, item) -> bool:
        return item == self.name or item == self.id


class UserList:
    def __init__(self, users: typing.List[User] | None = ...) -> None:
        """
        initialize a list for all users and start garbage-collector

        special: ´´get_user´´ function (gets a user by its name or encryption key)
        """
        self._users = users if users is not ... else list()
        self.client_threads = list()

        self.executor = ThreadPoolExecutor()
        self.collector = self.executor.submit(self._garbage_collector, .5)

        self.loop = True

    @property
    def names(self) -> typing.Generator:
        """
        return the names of all users
        """
        for element in self._users:
            yield element.name

    def sendall(self, message: iter) -> None:
        for user in self._users:
            user.send({
                "time": time.time(),
                "content": message
            }, force=True)

    def append(self, obj: User) -> None:
        """
        append object to the end of the list and start receive thread
        """
        if obj.name in self:
            self.remove_by(name=obj.name)

        self.client_threads.append(self.executor.submit(obj.receive))
        self._users.append(obj)

    def get_user(self, name: str | None = ..., user_id: str | None = ...) -> User:
        """
        get a user by its name or encryption key
        """
        for element in self._users:
            if name is not ...:
                if name in element:
                    return element

            if user_id is not ...:
                if user_id in element:
                    return element
        raise KeyError(f'No User with name {name} or id {user_id} found!')

    def remove(self, user: User) -> None:
        """
        remove a user by its class
        """
        user.end()
        self._users.remove(user)

    def remove_by(self, *args, **kw) -> None:
        """
        remove a user by its username or encryption key

        arguments are the same as for UserList.get_user
        """
        self.remove(self.get_user(*args, **kw))

    def reset(self) -> None:
        """
        reset all users (clear self._users)
        """
        for user in self._users:
            user.send({'warning': 'server_logout'}, message_type="disconnect", force=True)
            user.end()
        self._users = list()

    def _garbage_collector(self, time_between_loops: float | None = .5) -> None:
        """
        check if any of the clients is disconnected and if yes, remove it
        """
        while self.loop:
            for element in self._users:
                if element.disconnect:
                    element.end()
                    self._users.remove(element)
            time.sleep(time_between_loops)

    def end(self) -> None:
        """
        shutdown all threads
        """
        self.loop = False
        for user in self._users:
            user.end()
        self.executor.shutdown(wait=False)

    def __iter__(self) -> typing.Iterator:
        for element in self._users:
            yield element

    def __contains__(self, other: str) -> bool:
        with contextlib.suppress(KeyError):
            self.get_user(name=other, user_id=other)
            return True
        return False

    def __str__(self) -> str:
        return f"<class UserList (users={list(self.names)}, running={self.__bool__()})>"

    def __repr__(self) -> str:
        return self.__str__()

    def __bool__(self) -> bool:
        """
        return True if AuthKey
        """
        return self.loop


class Future:
    def __init__(self) -> None:
        self.__value: typing.Any | None = ...

    @property
    def result(self) -> typing.Any:
        if self.__value is not ...:
            return self.__value
        raise ValueError("No value received yet")

    @result.setter
    def result(self, value) -> None:
        self.__value = value

    def __repr__(self) -> str:
        return f"<future: result={self.__value is not ...}>"

    def __bool__(self) -> bool:
        """
        return True if AuthKey
        """
        return self.__value is not ...


class Daytime:
    """
    class for calculating with HH:MM:SS
    """
    def __init__(self, hour: int = 0, minute: int = 0, second: int = 0) -> None:
        self.hour = hour
        self.minute = minute
        self.second = second

    @property
    def hour(self) -> int:
        return self.__hour

    @hour.setter
    def hour(self, value: int) -> None:
        self.__hour = value % 24
        while self.__hour < 0:
            self.__hour += 24

    @property
    def minute(self) -> int:
        return self.__minute

    @minute.setter
    def minute(self, value: int) -> None:
        self.__minute = value % 60
        while self.__minute < 0:
            self.__minute += 60

    @property
    def second(self) -> int:
        return self.__second

    @second.setter
    def second(self, value: int) -> None:
        self.__second = value % 60
        while self.__second < 0:
            self.__second += 60

    @staticmethod
    def from_abs(absolute_value: int) -> "Daytime":
        """
        convert an absolute value (seconds) to a Daytime

        :param absolute_value: the absolute time value in seconds
        """
        if type(absolute_value) != int:
            raise ValueError("only accepts of type int")

        # making sure the value is in range of the 24 hour time format
        while absolute_value < 0:
            absolute_value += 24*3600

        while absolute_value > 24*3600:
            absolute_value -= 24*3600

        # splitting up in Hour, Minute, Second
        hour = absolute_value // 3600
        absolute_value -= hour * 3600
        minute = absolute_value // 60
        absolute_value -= minute * 60
        return Daytime(hour=hour, minute=minute, second=absolute_value)

    @staticmethod
    def from_strftime(string_time: str, sep: str = ":") -> "Daytime":
        """
        from format "HH:MM:SS"
        """
        parts = string_time.split(sep)
        parts += ["00"] * (3-len(parts))
        return Daytime(hour=int(parts[0]), minute=int(parts[1]), second=int(parts[2]))

    @staticmethod
    def now() -> "Daytime":
        """
        Daytime object with current time
        """
        return Daytime(hour=int(time.strftime("%H")), minute=int(time.strftime("%M")), second=int(time.strftime("%S")))

    # mathematics
    def __add__(self, other: "Daytime") -> "Daytime":
        return Daytime.from_abs(abs(self) + abs(other))

    def __iadd__(self, other: "Daytime") -> "Daytime":
        self.__dict__ = self.__add__(other).__dict__
        return self

    def __sub__(self, other: "Daytime") -> "Daytime":
        return Daytime.from_abs(abs(self) - abs(other))

    def __isub__(self, other: "Daytime") -> "Daytime":
        self.__dict__ = self.__sub__(other).__dict__
        return self

    # comparison
    def __eq__(self, other: "Daytime") -> bool:
        return abs(self) == abs(other)

    def __ne__(self, other: "Daytime") -> bool:
        return abs(self) != abs(other)

    def __lt__(self, other: "Daytime") -> bool:
        return abs(self) < abs(other)

    def __le__(self, other: "Daytime") -> bool:
        return abs(self) <= abs(other)

    def __gt__(self, other: "Daytime") -> bool:
        return abs(self) > abs(other)

    def __ge__(self, other: "Daytime") -> bool:
        return abs(self) >= abs(other)

    # representation
    def __str__(self) -> str:
        return f"{'0' if self.hour < 10 else ''}{self.hour}:{'0' if self.minute < 10 else ''}{self.__minute}:{'0' if self.second < 10 else ''}{self.__second}"

    def to_string(self) -> str:
        """
        call __str__
        """
        return self.__str__()

    def __repr__(self) -> str:
        return f"<Daytime: {self.__str__()}>"

    def __bool__(self) -> bool:
        return bool(self.__abs__())

    def __abs__(self) -> int:
        """
        returns time in seconds
        """
        return self.hour * 3600 + self.minute * 60 + self.second

    # accessibility
    def __getitem__(self, item: str) -> int:
        match item:
            case "hour":
                return self.hour
            case "minute":
                return self.minute
            case "second":
                return self.second
            case _:
                raise ValueError(f"{item} is not a valid variable!")

    def __setitem__(self, item: str, value: int) -> None:
        match item:
            case "hour":
                self.hour = value
            case "minute":
                self.minute = value
            case "second":
                self.second = value
            case _:
                raise ValueError(f"{item} is not a valid variable!")

    def __delitem__(self, item: str) -> None:
        match item:
            case "hour":
                self.hour = 0
            case "minute":
                self.minute = 0
            case "second":
                self.second = 0
            case _:
                raise ValueError(f"{item} is not a valid variable!")
