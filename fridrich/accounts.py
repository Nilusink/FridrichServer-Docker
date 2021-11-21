"""
used for managing user Accounts
(Server)

Author: Nilusink
"""
from threading import Thread
from fridrich import *
import json


class Manager:
    """
    account manager
    """
    # _instance = None

    # def __new__(cls, *args, **kw):
    # """
    # check if the class already exists
    # """
    # if cls._instance is None:
    #     cls._instance = super(Manager, cls).__new__(cls)
    # return cls._instance

    def __init__(self, account_file: str) -> None:
        """
        account_file - file to store encrypted account data in
        """
        self.__encryptionFile = account_file
        tmp = json.load(open(self.__encryptionFile, 'r'))
        for element in tmp:
            element["pwd"] = cryption_tools.High.decrypt(element["pwd"])
        self.__accounts = tmp

    def update_file(self, thread: bool | None = True) -> None:
        """
        write changed accounts to file
        """
        if thread:
            Thread(target=self.update_file, kwargs={"thread": False})
            return

        tmp = list()
        for account in self.__accounts:
            print(f"encrypting: {account}")
            temp = account.copy()
            temp["pwd"] = cryption_tools.High.encrypt(temp["pwd"])
            tmp.append(temp)
        print("encrypted, writing...")
        with open(self.__encryptionFile, 'w') as out:
            json.dump(tmp, out)
        print("done writing file")

    def get_accounts(self) -> list:
        """
        get account data
        """
        return self.__accounts

    def __write_accounts(self, accounts: list) -> None:
        """
        write account file
        """
        self.__accounts = accounts

    def set_pwd(self, username: str, new_password: str) -> None:
        """
        set password of given user
        """
        for element in self.__accounts:
            if element['Name'] == username:
                element['pwd'] = new_password  # if user is selected user, change its password
                break    # to not further iterate all users

        self.__write_accounts(self.__accounts)    # write output to file

    def set_username(self, old_user: str, new_user: str) -> None:
        """
        change username
        """
        UsedNames = useful.List.get_inner_dict_values(self.__accounts, 'Name')

        element = str()
        i = int()

        if new_user not in UsedNames+[name+'2' for name in UsedNames]:  # name+'2' because the double-vote agent uses this for their votes
            for i, element in enumerate(self.__accounts):
                if element['Name'] == old_user:
                    element['Name'] = new_user  # if user is selected user, change its password
                    continue    # to not further iterate all users and get i value of element

            self.__accounts[i] = element    # make sure the new element is in list and on correct position

            self.__write_accounts(self.__accounts)  # write output to file
            return
        raise NameError('Username already exists')

    def set_user_sec(self, username: str, security_clearance: str) -> None:
        """
        set clearance of user
        """
        element = str()
        i = int()

        for i, element in enumerate(self.__accounts):
            if element['Name'] == username:
                element['sec'] = security_clearance  # if user is selected user, change its security clearance
                continue    # to not further iterate all users and get i value of element

        self.__accounts[i] = element    # make sure the new element is in list and on correct position

    def new_user(self, username: str, password: str, security_clearance: str) -> None:
        """
        add new user
        """
        UsedNames = useful.List.get_inner_dict_values(self.__accounts, 'Name')

        if username in UsedNames:
            return

        self.__accounts.append({'Name': username, 'pwd': password, 'sec': security_clearance})  # create user
    
    def remove_user(self, username: str) -> None:
        """
        remove a user
        """
        accounts = self.get_accounts()   # get accounts
        for i in range(len(accounts)):  # iterate accounts
            if accounts[i]['Name'] == username:  # if account name is username
                accounts.pop(i)  # remove user
                break
        
        self.__write_accounts(accounts)    # update accounts

    def verify(self, username: str, password: str) -> None | str:
        """
        return False or user security Clearance
        """
        users = self.get_accounts()  # get accounts
        Auth = False
        for element in users:   # iterate users
            if username == element['Name'] and password == element['pwd']:  # if username is account name
                if 'sec' in element:
                    Auth = element['sec']   # set element 'sec' of user
                    if Auth == '':
                        Auth = None
                else:
                    Auth = None

        return Auth  # return result
