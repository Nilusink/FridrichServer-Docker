#! /usr/bin/python3
"""
main program for the Server

Author: Nilusink
"""
from traceback import format_exc
from contextlib import suppress
from threading import Thread
from os import system
import sys

from cryptography.fernet import InvalidToken

# local imports
from fridrich.cryption_tools import key_func, MesCryp
from fridrich.accounts import Manager
from fridrich.server_funcs import *
from fridrich.new_types import *
from fridrich import app_store

Const = Constants()
debug = Debug(Const.SerlogFile, Const.errFile)

client: socket.socket

Users = UserList()


def send_success(user: User, message: dict) -> None:
    """
    send the success message to the client
    """
    mes = {
        "time": message['time'],
        "content": {'Success': 'Done'}
    }
    user.send(mes)
    

def verify(username: str, password: str, cl: socket.socket, address: str) -> None:
    """
    verify the client and send result
    """
    resp = AccManager.verify(username, password)
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
        new_user = User(name=username, sec=resp, key=key, cl=cl, ip=address, function_manager=FunManager.exec)
        Users.append(new_user)
        
    debug.debug(new_user)   # print out username, if connected successfully or not and if it is a bot
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


# @debug_send_traceback
@debug.catch_traceback
def client_handler() -> None:
    """
    Handles communication with all clients
    """
    try:
        cl, address = server.accept()
        address = address[0]
        debug.debug(f'Connected to {address}')
    except OSError:
        return
    # try to load the message, else ignore it and restart
    try:
        t_mes = cryption_tools.MesCryp.decrypt(cl.recv(2048))

    except InvalidToken:
        Communication.send(cl, {'error': 'MessageError', 'info': "Couldn'T decrypt message with default key"}, encryption=MesCryp.encrypt)
        return

    mes = json.loads(t_mes)
    if mes['type'] == 'auth':   # authorization function
        verify(mes['Name'], mes['pwd'], cl, address)
        return

    else:
        Communication.send(cl, {'error': 'AuthError', 'info': 'user must be logged in to user functions'}, encryption=MesCryp.encrypt)
        return


@debug.catch_traceback
def zero_switch(s_time: str | None = '00:00') -> None:
    """
    if time is s_time, execute the switch
    """
    if time.strftime('%H:%M') == s_time:
        with open(Const.lastFile, 'w') as output:    # get newest version of the "votes" dict and write it to the lastFile
            with open(Const.nowFile, 'r') as inp:
                last = inp.read()
                output.write(last)

        Vote.set({'GayKing': {}})
        
        # ---- Log File (only for GayKing Voting)
        last = json.loads(last)['GayKing']  # get last ones

        votes1 = int()
        attds = dict()
        for element in last:    # create a dict with all names and a corresponding value of 0
            attds[last[element]] = 0

        for element in last:    # if name has been voted, add a 1 to its sum
            votes1 += 1
            attds[last[element]] += 1

        highest = str()
        HighestInt = int()
        for element in attds:   # gets the highest of the recently created dict
            if attds[element] > HighestInt:
                HighestInt = attds[element]
                highest = element

            elif attds[element] == HighestInt:
                highest += '|'+element
        
        if HighestInt != 0:
            KingVar[time.strftime('%d.%m.%Y')] = highest
            
            debug.debug(f"backed up files and logged the GayKing ({time.strftime('%H:%M')})\nGayking: {highest}")
        
        else:
            debug.debug('no votes received')
        if time.strftime('%a') == Const.DoubleVoteResetDay:  # if Monday, reset double votes
            dVotes = DV.value.get()
            for element in dVotes:
                dVotes[element] = Const.DoubleVotes
            DV.value.set(dVotes)

        time.sleep(61)


@debug.catch_traceback
def auto_reboot(r_time: str | None = "03:00") -> None:
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

        self.value = new_types.FileVar(value, self.filePath)

    def vote(self, vote: str, user: str) -> bool:
        """
        if the user has any double votes left,

        vote as "double-user"
        """
        global Vote

        value = self.value.get()
        tmp = Vote.get()
        if user in value:
            if value[user] < 1:
                return False
            try:
                tmp['GayKing'][user+'2'] = vote
            except KeyError:
                tmp['GayKing'] = dict()
                tmp['GayKing'][user+'2'] = vote

            value[user] -= 1
            self.value.set(value)
            Vote.set(tmp)
            return True
        
        value[user] = 0
        self.value.set(value)
        return False

    def unvote(self, user: str, voting: str) -> None:
        """
        unvote DoubleVote
        """
        global Vote
        tmp = Vote.get()
        with suppress(KeyError):
            tmp[voting].pop(user+'2')
        
            value = self.value.get()
            value[user] += 1
            self.value.set(value)
        Vote.set(tmp)

    def get_frees(self, user: str) -> int:
        """
        returns the free double-votes for the given users
        """
        value = self.value.get()
        if user in value:
            return value[user]

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
                'gOuser': ClientFuncs.get_online_users
            },
            'user': {                                  # instead of 5 billion if'S
                'vote': ClientFuncs.vote,
                'unvote': ClientFuncs.unvote,
                'dvote': ClientFuncs.double_vote,
                'dUvote': ClientFuncs.double_unvote,
                'getVote': ClientFuncs.get_vote,
                'getFrees': ClientFuncs.get_free_votes,
                'CalEntry': ClientFuncs.calendar_handler,
                'req': ClientFuncs.req_handler,
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
                "modify_app": app_store.modify_app
            },
            'guest': {                                  # instead of 5 billion if'S
                'CalEntry': ClientFuncs.calendar_handler,
                'getVersion': ClientFuncs.get_version,
                'getVote': ClientFuncs.get_vote,
                'req': ClientFuncs.req_handler,
                'end': ClientFuncs.end
            },
            'bot': {
                'setVersion': ClientFuncs.set_version,
                'getVersion': ClientFuncs.get_version,
                'end': ClientFuncs.end
            }
        }

    @debug.catch_traceback
    def exec(self, message: dict, user: User) -> typing.Tuple[bool, typing.Any] | typing.Tuple[str, str]:
        """
        execute the requested function or return error
        """
        if user.sec in self.switch:
            if message['type'] in self.switch[user.sec]:
                self.switch[user.sec][message['type']](message, user)
                return False, None
            
            else:
                isIn = False
                req = list()
                for element in self.switch:
                    if message['type'] in self.switch[element]:
                        isIn = True
                        req.append(element)
                
                if isIn:
                    debug.debug(f'user {user.sec} tried to use function {message["type"]} ({req})')
                    return 'ClearanceIssue', f'Clearance required: {req}'
                
                else:
                    return 'InvalidRequest', f'Invalid Request: {message["type"]}'

        else:
            return 'ClearanceIssue', f'Clearance not set: {user.sec}'


class AdminFuncs:
    """
    Manages the Admin Functions
    """
    @staticmethod
    def get_accounts(message: dict, user: User, *_args) -> None:
        """
        get all users | passwords | clearances
        """
        mes = {
            "time": message["time"],
            "content": AccManager.get_accounts()  # getting and decrypting accounts list
        }

        user.send(mes)  # sending list to client
    
    @staticmethod
    def set_password(message: dict, user: User, *_args) -> None:
        """
        set a new password for the given user
        """
        AccManager.set_pwd(message['User'], message['newPwd'])   # set new password
        send_success(user, message)  # send success

    @staticmethod
    def set_username(message: dict, user: User, *_args) -> None:
        """
        change the username for the given user
        """
        AccManager.set_username(message['OldUser'], message['NewUser'])  # change account name
        send_success(user, message)  # send success
    
    @staticmethod
    def set_security(message: dict, user: User, *_args) -> None:
        """
        change the clearance for the given user
        """
        AccManager.set_user_sec(message['Name'], message['sec'])
        send_success(user, message)

    @staticmethod
    def add_user(message: dict, user: User, *_args) -> None:
        """
        add a new user with set name, password and clearance
        """
        AccManager.new_user(message['Name'], message['pwd'], message['sec'])
        send_success(user, message)
    
    @staticmethod
    def remove_user(message: dict, user: User, *_args) -> None:
        """
        remove user by username
        """
        AccManager.remove_user(message['Name'])
        send_success(user, message)

    @staticmethod
    def reset_user_logins(*_args) -> None:
        """
        reset all current logins (clear the Users variable)
        """
        global Users
        Users.reset()

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
        tmp[message['voting']][user.name] = resp
        Vote.set(tmp)    # set vote
        debug.debug(f'got vote: {message["vote"]}                     .')   # print that it received vote (debugging)

        send_success(user, message)

    @staticmethod
    def unvote(message: dict, user: User, *_args) -> None:
        """
        unvote a user
        """
        global Vote
        tmp = Vote.get()
        with suppress(KeyError): 
            del tmp[message['voting']][user.name]  # try to remove vote from client, if client hasn't voted yet, ignore it
        Vote.set(tmp)
        send_success(user, message)

    @staticmethod
    def calendar_handler(message: dict, user: User, *_args) -> None:
        """
        Handle the Calendar requests/write
        """
        calendar = json.load(open(Const.CalFile, 'r'))
        if not message['event'] in calendar[message['date']]:    # if event is not there yet, create it
            try:
                calendar[message['date']].append(message['event'])
            except (KeyError, AttributeError):
                calendar[message['date']] = [message['event']]

            json.dump(calendar, open(Const.CalFile, 'w'))  # update fil
            debug.debug(f'got Calender: {message["date"]} - "{message["event"]}"')    # notify that there has been a calendar entry
        
        send_success(user, message)

    @staticmethod
    def req_handler(message: dict, user: User, *_args) -> None:
        """
        Handle some default requests / logs
        """
        global reqCounter, Vote
        reqCounter += 1
        if message['reqType'] == 'now':   # now is for the current "votes" dictionary
            with open(Const.nowFile, 'r') as inp:
                mes = {
                    "content": json.load(inp),
                    "time": message["time"]
                }
                user.send(mes)

        elif message['reqType'] == 'last':  # last is for the "votes" dictionary of the last day
            with open(Const.lastFile, 'r') as inp:
                mes = {
                    "content": json.load(inp),
                    "time": message["time"]
                }
                user.send(mes)
                
        elif message['reqType'] == 'log':   # returns the log of the GayKings
            with open(Const.KingFile, 'r') as inp:
                mes = {
                    "content": json.load(inp),
                    "time": message["time"]
                }
                user.send(mes)
                
        elif message['reqType'] == 'attds':  # returns All attendants (also non standard users)
            new_ones = get_new_ones(message['atype'], Vote, Const.lastFile, message['voting'])
            mes = {
                "content": {'Names': ['Lukas', 'Niclas', 'Melvin']+new_ones},
                "time": message["time"]
            }
            user.send(mes)    # return standard users + new ones
                
        elif message['reqType'] == 'temps':  # returns the temperatures
            global temps
            mes = {
                "content": {'Room': temps["temp"], 'CPU': temps["cptemp"], 'Hum': temps["hum"]},
                "time": message["time"]
            }
            user.send(mes)
                
        elif message['reqType'] == 'cal':   # returns the calendar dictionary
            with open(Const.CalFile, 'r') as inp:
                mes = {
                    "content": json.load(inp),
                    "time": message["time"]
                }
                user.send(mes)
                
        else:   # notify if an invalid request has been sent
            debug.debug(f'Invalid Request {message["reqType"]} from user {user.name}')

    @staticmethod
    def change_pwd(message: dict, user: User,  *_args) -> None:
        """
        change the password of the user (only for logged in user)
        """
        validUsers = json.loads(cryption_tools.Low.decrypt(open(Const.crypFile, 'r').read()))
        for element in validUsers:
            if element['Name'] == user.name:
                element['pwd'] = message['newPwd']
        
        with open(Const.crypFile, 'w') as output:
            fstring = json.dumps(validUsers, ensure_ascii=False)
            c_string = cryption_tools.Low.encrypt(fstring)
            output.write(c_string)
        
        send_success(user, message)

    @staticmethod
    def get_vote(message: dict, user: User, *_args) -> None:
        """
        get the vote of the logged-in user
        """
        if 'flag' in message:
            x = '2' if message['flag'] == 'double' else ''
        else:
            x = ''

        name = user.name + x
        if not message['voting'] in Vote.get():
            mes = {
                "content": {'Error': 'NotVoted'},
                "time": message['time']
            }
            user.send(mes)
            return

        if name not in Vote[message['voting']]:
            mes = {
                "content": {'Error': 'NotVoted'},
                "time": message["time"]
            }
            user.send(mes)
            return
        cVote = Vote[message['voting']][name]
        mes = {
            "content": {'Vote': cVote, 'time': message['time']},
            "time": message["time"]
        }
        user.send(mes)

    @staticmethod
    def get_version(message: dict, user: User, *_args) -> None:
        """
        read the Version variable
        """
        vers = open(Const.versFile, 'r').read()
        mes = {
            "content": {'Version': vers},
            "time": message["time"]
        }
        user.send(mes)

    @staticmethod
    def set_version(message: dict, user: User, *_args) -> None:
        """
        set the version variable
        """
        with open(Const.versFile, 'w') as output:
            output.write(message['version'])

        send_success(user, message)

    @staticmethod
    def double_vote(message: dict, user: User, *_args) -> None:
        """
        double vote
        """
        name = user.name
        resp = check_if(message['vote'], Vote.get(), message['voting'])     
        resp = DV.vote(resp, name)
        if resp:
            send_success(user, message)
        else:
            mes = {
                "content": {'Error': 'NoVotes'},
                "time": message["time"]
            }
            user.send(mes)

    @staticmethod
    def double_unvote(message: dict, user: User, *_args) -> None:
        """
        double unvote
        """
        global DV
        name = user.name
        DV.unvote(name, message['voting'])
        send_success(user, message)

    @staticmethod
    def get_free_votes(message: dict, user: User, *_args) -> None:
        """
        get free double votes of logged in user
        """
        global DV
        name = user.name
        frees = DV.get_frees(name)

        if frees is False and frees != 0:
            mes = {
                "content": {'Error': 'RegistryError'},
                "time": message["time"]
            }
            user.send(mes)
            return
        mes = {
            "content": {'Value': frees},
            "time": message["time"]
        }
        user.send(mes)

    @staticmethod
    def get_online_users(message: dict, user: User, *_args) -> None:
        """
        get all logged in users
        """
        mes = {
            "content": {'users': list([t_user.name for t_user in Users])},
            "time": message["time"]
        }
        user.send(mes)

    @staticmethod
    def append_chat(message: dict, user: User, *_args) -> None:
        """
        Add message to chat
        """
        Chat.add(message['message'], user.name)
        send_success(user, message)

    @staticmethod
    def get_chat(message: dict, user: User, *_args) -> None:
        """
        get Chat
        """
        mes = {
            "content": Chat.get(),
            "time": message["time"]
        }
        user.send(mes)

    @staticmethod
    def get_all_vars(message: dict, user: User, *_args) -> None:
        """
        get all user controlled variables
        """
        _variables = dict()
        with suppress(FileNotFoundError):
            _variables = json.load(open(Const.VarsFile, 'r'))

        msg = {
            "content": _variables,
            "time": message["time"]
        }

        user.send(msg)

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
                "content": {"var": _variables[message["var"]]},
                "time": message["time"]
            }
        else:
            msg = {
                "content": {"Error": "KeyError", "info": {message['var']}},
                "time": message["time"]
            }
        user.send(msg)

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
        send_success(user, message)

    @staticmethod
    def del_var(message: dict, user: User, *_args) -> None:
        """
        delete a user controlled variable
        """
        tmp = json.load(open(Const.VarsFile, 'r'))
        if message["var"] in tmp:
            del tmp[message["var"]]
        else:   # if KeyError occurs
            user.send({"content": {"Error": "KeyError", "info": message["var"]}, "time": message["time"]})

        json.dump(tmp, open(Const.VarsFile, 'w'), indent=4)
        send_success(user, message)

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
    start = time.time()
    while not Const.Terminate:
        # --------  00:00 switch ---------
        zero_switch(Const.switchTime)

        # --------- daily reboot ---------
        auto_reboot(Const.rebootTime)

        # --------- Accounts File ---------
        if time.strftime("%M") in ("00", "15", "30", "45"):  # update every 15 minutes
            AccManager.update_file()


############################################################################
#                              Main Program                                #
############################################################################
if __name__ == '__main__':
    server = socket.socket()
    try:
        reqCounter = 0
        temps = {
                 "temp": float(),
                 "cptemp": float(),
                 "hum": float()
        }
        
        AccManager = Manager(Const.crypFile)
        FunManager = FunctionManager()

        Vote = FileVar(json.load(open(Const.nowFile, 'r')), (Const.nowFile))
        DV = DoubleVote(Const.doubFile)
        KingVar = FileVar(json.load(open(Const.KingFile, 'r')), (Const.KingFile))

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
