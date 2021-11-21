"""
used for any type on en/decryption
for fridrich (ex. End to End encryption,
password hashing, private config files
for the Client, ...)
(Server & Client)

Author: Nilusink
"""
import contextlib
import random
import math
import json
import os

# cryptography imports
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
import base64


class DecryptionError(Exception):
    pass


class NotEncryptedError(Exception):
    pass


class Extra:
    """
    extra functions
    """
    @staticmethod
    def median(string: str, medians: int) -> str:
        """
        split in medians number of parts and then reverse
        """
        parts = list()
        out = list()
        for i in range(1, medians+1):
            if not i == medians:
                parts.append([int((len(string)-1)/medians*(i-1)), int((len(string)-1)/medians*i)])
            else:
                parts.append([int((len(string)-1)/medians*(i-1)), len(string)])
        for part in parts:
            out.append(string[::-1][part[0]:part[1]])
        return ''.join(out[::-1])


class Low:
    @staticmethod
    def encrypt(string: str) -> str:
        """
        encrypt a string
        """
        out = str()
        for charter in string:
            part = str(math.sqrt(ord(charter)-20))
            out += str(base64.b85encode(part.encode('utf-16'))).lstrip("b'").rstrip("='")+' '
        return out

    @staticmethod
    def decrypt(string: str) -> str:
        """
        decrypt a string
        """
        try:
            out = str()
            parts = string.split(' ')
            for part in parts:
                s = (part+'=').encode()
                if not s == b'=':
                    part = float(base64.b85decode(part).decode('utf-16'))
                    out += chr(int(round(part**2+20, 0)))
            return out
        except ValueError:
            raise DecryptionError('Not a valid encrypted string!')


class High:
    @staticmethod
    def encrypt(string: str) -> str:
        """
        encrypt a string
        """
        temp1, temp2 = str(), str()
        for charter in string:
            temp1 += Low.encrypt((Extra.median(charter, 3)+' '))+' '
        for charter in Extra.median(temp1, 13):
            temp2 += str(ord(charter))+'|1|'
        temp2 = Low.encrypt(temp2)
        out = Extra.median(Extra.median(temp2, 152), 72)
        return Extra.median(str(base64.b85encode(out.encode('utf-32'))).lstrip("b'").rstrip("='")[::-1], 327)
    
    @staticmethod
    def decrypt(string: str) -> str:
        """
        decrypt a string
        """
        temp1, temp2 = str(), str()
        string = Extra.median(string, 327)[::-1]
        string = base64.b85decode(string).decode('utf-32')
        string = Extra.median(Extra.median(string, 72), 152)
        string = Low.decrypt(string)
        parts = string.split('|1|')
        for part in parts:
            with contextlib.suppress(ValueError):
                temp1 += chr(int(part))
        temp1 = Extra.median(temp1, 13)
        parts = temp1.split(' ')
        for part in parts:
            temp2 += Extra.median(Low.decrypt(part), 3)
        return temp2.replace('   ', '|tempspace|').replace(' ', '').replace('|tempspace|', ' ')


try:
    with open('/home/pi/Server/data/KeyFile.enc', 'r') as inp:
        defKey = Low.decrypt(inp.read()).lstrip("b'").rstrip("'").encode()

except FileNotFoundError:
    with open('data/KeyFile.enc', 'r') as inp:
        defKey = Low.decrypt(inp.read())


class MesCryp:
    """
    encryption/decryption for messages
    """
    @staticmethod
    def encrypt(string: str, key=None) -> bytes:
        """
        encrypt a string
        
        if a key is given, use it
        """
        if not key:
            key = defKey
        f = Fernet(key)
        encrypted = f.encrypt(string.encode('utf-8'))
        return encrypted    # returns bytes
    
    @staticmethod
    def decrypt(byte: bytes, key: bytes | None = defKey) -> str:
        """
        decrypt a bytes element
        """
        f = Fernet(key)
        decrypted = str(f.decrypt(byte)).lstrip("b'").rstrip("'")
        return decrypted    # returns string


def try_decrypt(message: bytes, client_keys: dict | list, errors=True) -> str | None:
    """
    try to decrypt a string with multiple methods
    """
    with contextlib.suppress(json.JSONDecodeError):
        mes = json.loads(message)
        if errors:
            raise NotEncryptedError('Message not encrypted')
        print(mes)
        return mes

    encMes = None
    for key in client_keys:
        with contextlib.suppress(InvalidToken, ValueError):
            encMes = MesCryp.decrypt(message, key.encode() if type(key) == str else b'')
            break
    
    if not encMes:
        with contextlib.suppress(InvalidToken):
            encMes = MesCryp.decrypt(message, defKey)
    
    if not encMes:
        print(encMes)
        print(message)
        return None

    try:
        jsonMes = json.loads(encMes)

    except json.JSONDecodeError:
        try:
            jsonMes = json.loads(message)

        except json.JSONDecodeError:
            return None
    return jsonMes


def key_func(length=10) -> str:
    """
    generate random key
    """
    String = 'abcdefghijklmnopqrstuvwxyz'                               # string for creating auth Keys
    String += String.upper()+'1234567890ß´^°!"§$%&/()=?`+*#.:,;µ@€<>|'

    password_provided = ''.join(random.sample(String, length))  # This is input in the form of a string
    password = password_provided.encode()  # Convert to type bytes
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
    return str(key).lstrip("b'").rstrip("'")


if __name__ == '__main__':
    from time import time
    try:
        while True:
            st = input('\n\nSentence? ')
            start = time()
            c = Extra.median(Low.encrypt(Extra.median(st, 12)), 6)
            e = Extra.median(Low.decrypt(Extra.median(c, 6)), 12)
            end = time()
            print('Low encryption:')
            print(c)
            print(e)
            print('\nencrypting and decrypting took:', round(end-start, 2))
            start = time()
            c = MesCryp.encrypt(string=st)
            e = MesCryp.decrypt(c, defKey.encode())
            end = time()
            print('Low encryption:')
            print(c)
            print(e)
            print('\nencrypting and decrypting took:', round(end-start, 2))
            input('Press enter to start High level encryption')
            print('\nHigh encryption:')
            start1 = time()
            c1 = High.encrypt(st)
            end1 = time()
            e1 = High.decrypt(c1)
            end2 = time()
            print(c1)
            print(e1)
            print('\nencrypting took:', round(end1-start1, 2))
            print('decrypting took:', round(end2-end1, 2))
            input('\npress enter to continue\n\n')

    except KeyboardInterrupt:
        print('Closing Client...')
        exit()
