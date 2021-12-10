#! /usr/bin/python3
"""
main program for the Server

Author: Nilusink
"""
from traceback import format_exc
from contextlib import suppress
from threading import Thread
from os import system
import numpy as np
import sys

from cryptography.fernet import InvalidToken

# local imports
from fridrich.server.accounts import Manager
from fridrich.server.server_funcs import *
from fridrich.classes import *

from fridrich.server import WStationFuncs
from fridrich.server import UserTools
from fridrich.server import *

from fridrich.cryption_tools import key_func, MesCryp
from fridrich import app_store

COM_PROTOCOL_VERSIONS: set = {"1.1.0", "1.1.1"}

client: socket.socket
Users = UserList()

debug = Debug(Const.SerlogFile, Const.errFile)


def verify(username: str, password: str, cl: socket.socket, address: str) -> None:
    """
    verify the client and send result
    """
    resp, logged_in_user = AccManager.verify(username, password)
    IsValid = False
    key = None
    new_user = None
    if resp is None:
        print(f"invalid auth from {address} ({username})")
        Communication.send(cl, {'Error': 'SecurityNotSet', 'info': f'no information about security clearance for user {username}'}, encryption=MesCryp.encrypt)
        return

    elif resp:
        IsValid = True
        key = key_func(length=30)
        new_user = User(name=logged_in_user["Name"], sec=logged_in_user["sec"], key=key, user_id=logged_in_user["id"], cl=cl, ip=address, function_manager=FunManager.exec, debugger=debug)
        Users.append(new_user)
        
    debug.debug(f"Connected to {new_user}, {IsValid=}")   # print out username, if connected successfully or not and if it is a bot
    mes = cryption_tools.MesCryp.encrypt(json.dumps({'Auth': IsValid, 'AuthKey': key}))
    cl.send(mes)


def debug_send_traceback(func: types.FunctionType) -> typing.Callable:
    """
    execute function and send traceback to client
    """
    def wrapper(*args, **kw):
        global client
        try:
            return func(*args, **kw)

        except Exception as ex:
            with suppress(BrokenPipeError):
                error = str(type(ex)).split("'")[1]
                info = str(ex)
                fullTraceback = format_exc()
                with suppress(UnboundLocalError):
                    Communication.send(client, {'Error': error, 'info': info, 'full': fullTraceback})
                with suppress(OSError, AttributeError, UnboundLocalError):
                    client.close()

            debug.debug('Thread 1 error:')
            debug.debug(format_exc())
    return wrapper


@debug.catch_traceback
def client_handler() -> None:
    """
    Handles communication with all clients
    """
    try:
        cl, address = server.accept()
        address = address[0]

    except OSError:
        return
    # try to load the message, else ignore it and restart
    b = cl.recv(2048)
    try:
        t_mes = cryption_tools.MesCryp.decrypt(b)

    except InvalidToken:
        debug.debug(f"Received Message (undecryptable): {b.decode()}")
        Communication.send(cl, {'error': 'MessageError', 'info': "Couldn'T decrypt message with default key"}, encryption=MesCryp.encrypt)
        return

    mes = json.loads(t_mes)
    if "type" in mes and mes['type'] == 'auth':   # authorization function
        # instantly raise an error if the COM_PROTOCOL_VERSION is not compatible
        if mes["com_protocol_version"] not in COM_PROTOCOL_VERSIONS:
            debug.debug(f"Client tried to connect with COM_PROTOCOL_VERSION == {mes['com_protocol_version']}, allowed: {COM_PROTOCOL_VERSIONS}")
            Communication.send(cl, {
                "Error": "RuntimeError",
                "info": f"Invalid COM_PROTOCOL_VERSION"
            }, encryption=MesCryp.encrypt)

        verify(mes['Name'], mes['pwd'], cl, address)
        return

    else:
        Communication.send(cl, {'Error': 'AuthError', 'info': 'user must be logged in to user functions'}, encryption=MesCryp.encrypt)
        return


@debug.catch_traceback
def zero_switch() -> None:
    """
    execute the switch
    """
    for voting, res in Vote:
        log_out_file = Const.logDirec+voting+".json"
        vote_res = list(res.values())

        # get masters
        res_arr = np.array(vote_res)
        m_max = max([x for x in np.unique(res_arr, return_counts=True)[1]])
        masters = [master for master in np.unique(res_arr) if vote_res.count(master) == m_max]

        # if a person was vote from all contestants (and there were more than one contestants)
        strike = {res[list(res.keys())[0]]}.intersection(*[{element} for element in res.values()])
        if strike and len(res) > 1:
            strike = "|".join(strike)
            debug.debug(f"Strike in {voting}: {strike}")
            try:
                strikes = json.load(open(Const.strikeFile, "r"))
            except (json.decoder.JSONDecodeError, FileNotFoundError):
                strikes = {}

            if time.strftime('%d.%m.%Y') not in strikes:
                strikes[time.strftime('%d.%m.%Y')] = []

            strikes[time.strftime('%d.%m.%Y')].append((voting, strike))

        total_masters = "|".join(masters)
        # write to log (for each voting)
        try:
            log = json.load(open(log_out_file, "r"))

        except (json.decoder.JSONDecodeError, FileNotFoundError):
            log = {}

        log[time.strftime('%d.%m.%Y')] = total_masters
        json.dump(log, open(log_out_file, "w"), indent=4)

        debug.debug(f"Results for {voting}: {total_masters}")

    # copy log to last log
    with open(Const.lastFile, "w") as output:
        json.dump(dict(Vote), output, indent=4)

    Vote.set({})
    debug.debug("done voting")

    if time.strftime('%a') == Const.DoubleVoteResetDay:  # if reset day, reset double votes
        dVotes = DV.value.get()
        for element in dVotes:
            dVotes[element] = Const.DoubleVotes
        DV.value.set(dVotes)


@debug.catch_traceback
def auto_reboot(r_time: str) -> None:
    """
    if time is r_time, reboot the server (format is "HH:MM")
    
    if you don't want the server to reboot, just set ``r_time`` to something like "99:99"

    or any other time that will never happen
    """
    if not len(r_time) == 5 and r_time.replace(':', '').isnumeric():
        raise InvalidStringError('r_time needs to be formatted like this: HH:MM')

    if time.strftime('%H:%M') == r_time:
        time.sleep(55)
        system('sudo reboot')


class DoubleVote:
    """
    Handle Double Votes
    """
    def __init__(self, file_path: str) -> None:
        """
        filePath: path to file where double votes are saved
        """
        self.filePath = file_path

        try:
            value = json.load(open(self.filePath, 'r'))

        except FileNotFoundError:
            value = dict()
            validUsers = json.load(open(Const.crypFile, 'r'))
            for element in validUsers:
                value[element['Name']] = 1

        self.value = classes.FileVar(value, self.filePath)

    def vote(self, vote: str, user_id: int) -> bool:
        """
        if the user has any double votes left,

        vote as "double-user"
        """
        global Vote

        user_id = str(user_id)

        value = self.value.get()
        tmp = Vote.get()
        if user_id in value:
            if value[user_id] < 1:
                return False
            try:
                tmp['GayKing'][user_id+'2'] = vote
            except KeyError:
                tmp['GayKing'] = dict()
                tmp['GayKing'][user_id+'2'] = vote

            value[user_id] -= 1
            self.value.set(value)
            Vote.set(tmp)
            return True
        
        value[user_id] = 1
        self.value.set(value)
        return False

    def unvote(self, user_id: int, voting: str) -> None:
        """
        unvote DoubleVote
        """
        global Vote
        tmp = Vote.get()
        with suppress(KeyError):
            tmp[voting].pop(str(user_id)+'2')
        
            value = self.value.get()
            value[user_id] += 1
            self.value.set(value)
        Vote.set(tmp)

    def get_frees(self, user_id: int) -> int:
        """
        returns the free double-votes for the given users
        """
        value = self.value.get()
        if user_id in value:
            return value[user_id]
        return False


class FunctionManager:
    """
    manages the requested functions
    """
    def __init__(self):
        """
        init switch dict
        """
        self.switch = {
            'admin': {
                'getUsers': AdminFuncs.get_accounts,
                'setPwd': AdminFuncs.set_password,
                'setName': AdminFuncs.set_username,
                'setSec': AdminFuncs.set_security,
                'newUser': AdminFuncs.add_user,
                'removeUser': AdminFuncs.remove_user,
                'end': AdminFuncs.end,
                'rsLogins': AdminFuncs.reset_user_logins,

                'setVersion': ClientFuncs.set_version,
                'getVersion': ClientFuncs.set_version,
                'gOuser': ClientFuncs.get_online_users,

                "ping": UserTools.ping,
                "trigger_voting": AdminFuncs.manual_voting
            },
            'user': {                                  # instead of 5 billion if'S
                'vote': ClientFuncs.vote,
                'unvote': ClientFuncs.unvote,
                'dvote': ClientFuncs.double_vote,
                'dUvote': ClientFuncs.double_unvote,
                'getVote': ClientFuncs.get_vote,
                'getFrees': ClientFuncs.get_free_votes,
                'CalEntry': ClientFuncs.calendar_handler,

                "gRes": ClientFuncs.results,
                "gLog": ClientFuncs.get_log,
                "gCal": ClientFuncs.get_cal,

                'end': ClientFuncs.end,
                'changePwd': ClientFuncs.change_pwd,
                'getVersion': ClientFuncs.get_version,
                'gOuser': ClientFuncs.get_online_users,
                'appendChat': ClientFuncs.append_chat,
                'getChat': ClientFuncs.get_chat,
                'get_all_vars': ClientFuncs.get_all_vars,
                'get_var': ClientFuncs.get_var,
                'set_var': ClientFuncs.set_var,
                'del_var': ClientFuncs.del_var,

                'get_apps': app_store.send_apps,
                'download_app': app_store.download_app,
                'create_app': app_store.receive_app,
                "modify_app": app_store.modify_app,
                
                "ping": UserTools.ping,
                "get_time":  UserTools.get_time,

                "get_temps": WStationFuncs.get_all
            },
            'guest': {                                  # instead of 5 billion if'S
                'CalEntry': ClientFuncs.calendar_handler,
                'getVersion': ClientFuncs.get_version,
                'getVote': ClientFuncs.get_vote,
                'end': ClientFuncs.end,

                "gRes": ClientFuncs.results,
                "gLog": ClientFuncs.get_log,
                "gCal": ClientFuncs.get_cal,

                "ping": UserTools.ping
            },
            'bot': {
                'setVersion': ClientFuncs.set_version,
                'getVersion': ClientFuncs.get_version,
                'end': ClientFuncs.end,

                "ping": UserTools.ping
            },
            'w_station': {
                "register": WStationFuncs.register,
                "commit": WStationFuncs.commit_data
            },
            "all": {
                "secReq": UserTools.get_sec_clearance
            }
        }

    def exec(self, message: dict, user: User) -> None:
        """
        execute the requested function or return error
        """
        error: dict = {}
        if user.sec in self.switch:
            if message['type'] in self.switch[user.sec]:
                self.switch[user.sec][message['type']](message, user)

            elif message["type"] in self.switch["all"]:
                self.switch["all"][message['type']](message, user)
            
            else:
                isIn = False
                req = list()
                for element in self.switch:
                    if message['type'] in self.switch[element]:
                        isIn = True
                        req.append(element)
                
                if isIn:
                    debug.debug(f'user {user.sec} tried to use function {message["type"]} ({req})')
                    error = {
                        "Error": "ClearanceIssue",
                        "info": f'Clearance required: {req}'
                    }
                
                else:
                    error = {
                        "Error": "InvalidRequest",
                        "info": f'Invalid Request: {message["type"]}'
                    }

        else:
            error = {
                "Error": "ClearanceIssue",
                "info": f'Clearance not set: {user.sec}'
            }

        if error:
            user.send(error, message_type="Error")


class AdminFuncs:
    """
    Manages the Admin Functions
    """
    @staticmethod
    def get_accounts(_message: dict, user: User, *_args) -> None:
        """
        get all users | passwords | clearances
        """
        user.send(AccManager.get_accounts())  # sending list to client
    
    @staticmethod
    def set_password(message: dict, user: User, *_args) -> None:
        """
        set a new password for the given user
        """
        AccManager.set_pwd(message['User'], message['newPwd'])   # set new password
        send_success(user)  # send success

    @staticmethod
    def set_username(message: dict, user: User, *_args) -> None:
        """
        change the username for the given user
        """
        AccManager.set_username(message['OldUser'], message['NewUser'])  # change account name
        send_success(user)  # send success
    
    @staticmethod
    def set_security(message: dict, user: User, *_args) -> None:
        """
        change the clearance for the given user
        """
        AccManager.set_user_sec(message['Name'], message['sec'])
        send_success(user)

    @staticmethod
    def add_user(message: dict, user: User, *_args) -> None:
        """
        add a new user with set name, password and clearance
        """
        try:
            AccManager.new_user(message['Name'], message['pwd'], message['sec'])

        except NameError:
            user.send({"Error": "NameError", "info": "user already exists"}, message_type="Error")

        send_success(user)
    
    @staticmethod
    def remove_user(message: dict, user: User, *_args) -> None:
        """
        remove user by username
        """
        AccManager.remove_user(message['Name'])
        send_success(user)

    @staticmethod
    def reset_user_logins(*_args) -> None:
        """
        reset all current logins (clear the Users variable)
        """
        global Users
        Users.reset()

    @staticmethod
    def manual_voting(_message: dict, user: User, *_args) -> None:
        """
        trigger a manual voting
        """
        zero_switch()
        send_success(user)

    @staticmethod
    def end(_message: dict, user: User, *_args) -> None:
        """
        log-out user
        """
        with suppress(Exception):
            Users.remove(user)


class ClientFuncs:
    """
    Manages the Client Functions
    """

    @staticmethod
    def vote(message: dict, user: User, *_args) -> None:
        """
        vote a name

        votes user by username
        """
        resp = check_if(message['vote'], Vote.get(), message['voting'])

        if not message['voting'] in Vote.get():
            Vote.__setitem__(message['voting'], dict())

        tmp = Vote.get()
        tmp[message['voting']][str(user.id)] = resp
        Vote.set(tmp)  # set vote

        send_success(user)

    @staticmethod
    def unvote(message: dict, user: User, *_args) -> None:
        """
        unvote a user
        """
        global Vote
        tmp = Vote.get()
        with suppress(KeyError):
            debug.debug(
                f"voting: {tmp}, user id: {user.id}, userid in voting: {str(user.id) in tmp[message['voting']]}")
            del tmp[message['voting']][
                str(user.id)]  # try to remove vote from client, if client hasn't voted yet, ignore it
        Vote.set(tmp)
        send_success(user)

    @staticmethod
    def calendar_handler(message: dict, user: User, *_args) -> None:
        """
        Handle the Calendar requests/write
        """
        calendar = json.load(open(Const.CalFile, 'r'))
        if not message['event'] in calendar[message['date']]:  # if event is not there yet, create it
            try:
                calendar[message['date']].append(message['event'])
            except (KeyError, AttributeError):
                calendar[message['date']] = [message['event']]

            json.dump(calendar, open(Const.CalFile, 'w'))  # update fil
            debug.debug(
                f'got Calender: {message["date"]} - "{message["event"]}"')  # notify that there has been a calendar entry

        send_success(user)

    @staticmethod
    def results(message: dict, user: User, *_args) -> None:
        """
        handle results requests
        """
        match message["flag"]:
            case "now":
                with open(Const.nowFile, 'r') as inp:
                    user.send(json.load(inp))

            case "last":
                with open(Const.lastFile, 'r') as inp:
                    user.send(json.load(inp))

            case _:
                raise KeyError(f"no results type \"{message['flag']}\"")

    @staticmethod
    def get_log(_message: dict, user: User, *_args) -> None:
        """
        get the GayKings log
        """
        logs: typing.Dict[str, dict] = {}
        for log in os.listdir(Const.logDirec):
            with open(Const.logDirec+log, 'r') as inp:
                logs[log.rstrip(".json")] = json.load(inp)

        user.send(logs)

    @staticmethod
    def get_cal(_message: dict, user: User, *_args) -> None:
        """
        get the calendar dictionary
        """
        with open(Const.CalFile, 'r') as inp:
            user.send(json.load(inp))

    @staticmethod
    def change_pwd(message: dict, user: User, *_args) -> None:
        """
        change the password of the user (only for logged in user)
        """
        validUsers = AccManager.get_accounts()
        for element in validUsers:
            if element['id'] == user.id:
                element['pwd'] = message['newPwd']

        with open(Const.crypFile, 'w') as output:
            fstring = json.dumps(validUsers, ensure_ascii=False)
            c_string = cryption_tools.Low.encrypt(fstring)
            output.write(c_string)

        send_success(user)

    @staticmethod
    def get_vote(message: dict, user: User, *_args) -> None:
        """
        get the vote of the logged-in user
        """
        if 'flag' in message:
            x = '2' if message['flag'] == 'double' else ''
        else:
            x = ''

        name = str(user.id) + x
        if not message['voting'] in Vote.get():
            user.send({'Error': 'NotVoted'}, message_type="Error")
            return

        if name not in Vote[message['voting']]:
            user.send({'Error': 'NotVoted'}, message_type="Error")
            return
        cVote = Vote[message['voting']][name]

        user.send(cVote)

    @staticmethod
    def get_version(_message: dict, user: User, *_args) -> None:
        """
        read the Version variable
        """
        vers = open(Const.versFile, 'r').read()
        user.send(vers)

    @staticmethod
    def set_version(message: dict, user: User, *_args) -> None:
        """
        set the version variable
        """
        with open(Const.versFile, 'w') as output:
            output.write(message['version'])

        send_success(user)

    @staticmethod
    def double_vote(message: dict, user: User, *_args) -> None:
        """
        double vote
        """
        user_id = user.id
        resp = check_if(message['vote'], Vote.get(), message['voting'])
        resp = DV.vote(resp, user_id)
        if resp:
            send_success(user)
        else:
            user.send({'Error': 'NoVotes'}, message_type="Error")

    @staticmethod
    def double_unvote(message: dict, user: User, *_args) -> None:
        """
        double unvote
        """
        global DV
        user_id = user.id
        DV.unvote(user_id, message['voting'])
        send_success(user)

    @staticmethod
    def get_free_votes(_message: dict, user: User, *_args) -> None:
        """
        get free double votes of logged in user
        """
        global DV
        user_id = user.id
        frees = DV.get_frees(user_id)

        if frees is False and frees != 0:
            user.send({'Error': 'RegistryError'}, message_type="Error")
            return

        user.send({'Value': frees})

    @staticmethod
    def get_online_users(_message: dict, user: User, *_args) -> None:
        """
        get all logged in users
        """
        user.send(list([t_user.name for t_user in Users]))

    @staticmethod
    def append_chat(message: dict, user: User, *_args) -> None:
        """
        Add message to chat
        """
        Chat.add(message['message'], user.name)
        send_success(user)

    @staticmethod
    def get_chat(_message: dict, user: User, *_args) -> None:
        """
        get Chat
        """
        user.send(Chat.get())

    @staticmethod
    def get_all_vars(_message: dict, user: User, *_args) -> None:
        """
        get all user controlled variables
        """
        with suppress(FileNotFoundError):
            variables = json.load(open(Const.VarsFile, 'r'))

        user.send(variables)

    @staticmethod
    def get_var(message: dict, user: User, *_args) -> None:
        """
        get a user controlled variable
        """
        _variables = dict()
        with suppress(FileNotFoundError):
            _variables = json.load(open(Const.VarsFile, 'r'))

        if message["var"] in _variables:
            msg = {
                "var": _variables[message["var"]]
            }
        else:
            msg = {
                "Error": "KeyError",
                "info": {message['var']}
            }
        user.send(msg, message_type="Error")

    @staticmethod
    def set_var(message: dict, user: User, *_args) -> None:
        """
        set a user controlled variable
        """
        try:
            tmp = json.load(open(Const.VarsFile, 'r'))
            tmp[message["var"]] = message["value"]
        except FileNotFoundError:
            tmp = dict()
        json.dump(tmp, open(Const.VarsFile, 'w'), indent=4)
        send_success(user)

    @staticmethod
    def del_var(message: dict, user: User, *_args) -> None:
        """
        delete a user controlled variable
        """
        tmp = json.load(open(Const.VarsFile, 'r'))
        if message["var"] in tmp:
            del tmp[message["var"]]
        else:  # if KeyError occurs
            user.send({"Error": "KeyError", "info": message["var"]}, message_type="Error")

        json.dump(tmp, open(Const.VarsFile, 'w'), indent=4)
        send_success(user)

    @staticmethod
    def end(_message: dict, user: User, *_args) -> None:
        """
        clear logged in user
        """
        with suppress(Exception):
            Users.remove(user)


def receive() -> None:
    """
    Basically the whole server
    """
    while not Const.Terminate:
        client_handler()


def update() -> None:
    """
    updates every few seconds
    """
    global reqCounter
    while not Const.Terminate:
        # --------  00:00 switch ---------
        if time.strftime("%H:%M") == Const.switchTime:
            zero_switch()
            time.sleep(61)

        # --------- daily reboot ---------
        auto_reboot(Const.rebootTime)

        time.sleep(1)


############################################################################
#                              Main Program                                #
############################################################################
if __name__ == '__main__':
    server = socket.socket()
    try:
        reqCounter = 0

        AccManager = Manager(Const.crypFile)
        FunManager = FunctionManager()

        Vote = FileVar(json.load(open(Const.nowFile, 'r')), [Const.nowFile])
        DV = DoubleVote(Const.doubFile)

        with open(Const.logFile, 'w') as out:
            out.write('')

        dayRange = 30
        try:
            cal = json.load(open(Const.CalFile, 'r'))
            tod = datetime.datetime.now()
            for i in range(dayRange, 0, -1):
                d = datetime.timedelta(days=i)
                a = tod - d
                dForm = f'{a.day}.{a.month}.{a.year}'
                if dForm not in cal:
                    cal[dForm] = list()
            json.dump(cal, open(Const.CalFile, 'w'))

        except (KeyError, FileNotFoundError):
            cal = dict()
            tod = datetime.datetime.now()
            for i in range(dayRange, 0, -1):
                d = datetime.timedelta(days=i)
                a = tod - d
                dForm = f'{a.day}.{a.month}.{a.year}'
                cal[dForm] = list()
            json.dump(cal, open(Const.CalFile, 'w'))

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((Const.ip, Const.port))
        server.listen()
        debug.debug(Const.ip)

        Updater = Thread(target=update, daemon=True)

        Updater.start()

        receive()

    except Exception as e:
        with suppress(Exception):
            Users.end()
        with open(Const.errFile, 'a') as out:   # debug to file because there may be an error before the debug class was initialized
            out.write(f'######## - Exception "{e}" on {datetime.datetime.now().strftime("%H:%M:%S.%f")} - ########\n\n{format_exc()}\n\n######## - END OF EXCEPTION - ########\n\n\n')

        server.shutdown(socket.SHUT_RDWR)
        debug.debug(format_exc())
        Terminate = True
        sys.exit(0)
