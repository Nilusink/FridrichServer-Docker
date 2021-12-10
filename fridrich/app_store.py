"""
used for file-transfer and other AppStore
functions like modifying and creating Apps
(Server & Client)

Author: Nilusink
"""
from concurrent.futures import ThreadPoolExecutor, Future
from fridrich import classes
import socket
import struct
import time
import json
import os

download_progress: float = 0.0
download_program: str = ""

executor = ThreadPoolExecutor()


def get_list() -> list:
    """
    :return: a list of available apps with versions
    """
    with open("/home/pi/Server/fridrich/server/settings.json", 'r') as inp:
        directory = json.load(inp)["AppStoreDirectory"]

    apps = list()
    for app in [dire for dire in os.listdir(directory) if os.path.isdir(directory + '/' + dire)]:
        size = float()
        filenames = [file for file in os.listdir(directory+app) if file.endswith(".zip")]
        if "AppInfo.json" not in os.listdir(directory+app):
            continue

        for filename in filenames:
            size += os.path.getsize(directory+app+'/'+filename)

        app_info = json.load(open(directory+app+'/AppInfo.json'))
        app_info["name"] = app
        app_info["files"] = filenames
        app_info["size"] = size
        apps.append(app_info)

    return apps


def send_apps(_message: dict, user: classes.User) -> None:
    """
    :param _message: the message received from the client (not used)
    :param user: the user to send the answer to
    :return: None
    """
    user.send(get_list())


def download_app(message: dict, user: classes.User) -> None:
    """
    :param message: the message received from the client (for the timestamp)
    :param user: the user to send the answer to
    :return: None
    """
    with open("/home/pi/Server/fridrich/server/settings.json", 'r') as inp:
        directory = json.load(inp)["AppStoreDirectory"]

    files = tuple((file for file in os.listdir(directory+message["app"]) if file.endswith(".zip")))

    user.send(files)
    for file in files:
        send_receive(mode="send", filename=directory+message["app"]+'/'+file, destination=user.ip, print_steps=False)


def receive_app(message: dict, user: classes.User, modify: bool | None = False) -> None:
    """
    :param message: the message received from the client (for the timestamp)
    :param user: the user to send the answer to
    :param modify: if true used for modifying apps
    :return: None
    """
    with open("/home/pi/Server/fridrich/server/settings.json", 'r') as inp:
        directory = json.load(inp)["AppStoreDirectory"]+message["name"]

    if not modify:
        if os.path.isdir(directory):
            files = os.listdir(directory)
            if "AppInfo.json" in files:  # check if directory is empty, else send error
                user.send({"error": "ValueError", "info": f"App with name {message['name']} already exists"})
                return
            else:
                if len(files) != 0:
                    for element in files:
                        os.remove(directory+'/'+element)
        else:
            os.system(f"mkdir {directory}")

        with open(directory+"/AppInfo.json", 'w') as out:
            json.dump({
                       "version": message["version"],
                       "info": message["info"],
                       "publisher": user.name,
                       "publisher_id": user.id
            }, out, indent=4)

    user.send({"success": True})

    for _ in message["files"]:
        send_receive(mode='receive', print_steps=False, download_directory=directory, thread=False, overwrite=True)


def modify_app(message: dict, user: classes.User) -> None:
    """
            msg = {
            "type": "modify_app",
            "o_name": old_app_name,
            "name": app_name,
            "version": app_version,
            "info": app_info,
            "new": [file.split("/").split("\\")[-1] for file in files],
            "to_delete": to_delete
    """
    try:
        app = {app["name"]: app for app in get_list()}[message["o_name"]]
    except KeyError:
        user.send({
                "error": f"App {message['o_name']} doesn't exist"
            })
        return

    if app["publisher_id"] != user.id:
        user.send({
                "error": f"App can only be modified by creator! {app['publisher']}"
            })
        return

    if app["publisher"] != user.name:
        app["publisher"] = user.name

    with open("/home/pi/Server/fridrich/server/settings.json", 'r') as inp:
        directory = json.load(inp)["AppStoreDirectory"]

    with open(directory+"/"+app["name"]+"/AppInfo.json", 'w') as out:
        print(f"before: {app}")
        tmp = {
            "version": "nAn",
            "info": message["info"],
            "publisher": user.name,
            "publisher_id": app["publisher_id"]
        }
        print(f"after: {tmp}")
        json.dump(tmp, out, indent=4)

    for file in message["to_remove"]:
        os.remove(directory+'/'+app['name']+'/'+file)

    if message["name"] != app["name"]:
        os.system(f"mv {directory+'/'+app['name']+'/'} {directory+'/'+message['name']+'/'}")

    receive_app(message, user, modify=True)

    with open(directory+"/"+app["name"]+"/AppInfo.json", 'w') as out:
        tmp = {
            "version": message["version"],
            "info": message["info"],
            "publisher": user.name
        }
        json.dump(tmp, out, indent=4)


def send_receive(mode: str, filename: str | None = ..., destination: str | None = ..., print_steps: bool | None = False,
                 download_directory: str | None = ..., thread: bool | None = False, overwrite: bool | None = False) -> None | Future:
    """
    send and receive files (function version)

    :param mode: either 's' | 'send' or 'r' | 'receive'
    :param filename: filename for sending files
    :param destination: ip/hostname of destination computer
    :param print_steps: enables print function when receiving
    :param download_directory: where the downloaded files should end up
    :param thread: if the program should be executed as a thread or not
    :param overwrite: if true overwrites output file
    :return: None of Future instance of the Thread
    """
    global download_progress, download_program
    if thread:
        return executor.submit(send_receive, mode=mode, filename=filename, destination=destination, print_steps=print_steps,
                               download_directory=download_directory, thread=False, overwrite=overwrite)

    if mode in ('r', 'receive'):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', 15151))
        server.listen()

        client, address = server.accept()
        resp = json.loads(client.recv(1024).decode('utf-8'))
        download_program = resp["filename"]
        client.send('received'.encode('utf-8'))

        # receiving data
        if resp['type'] == "file":
            bs = client.recv(8)
            (length,) = struct.unpack('>Q', bs)
            data = b''
            no_rec = 0
            to_read = 0
            start = time.time()
            while len(data) < length:
                # doing it in batches is generally better than trying
                # to do it all in one go, so I believe.
                o_to_read = to_read
                to_read = length - len(data)
                data += client.recv(
                                    4096 if to_read > 4096 else to_read
                                    )

                download_progress = len(data)/length

                if to_read == o_to_read:    # check if new packages were received
                    no_rec += 1
                else:
                    no_rec = 0

                if no_rec >= 100:          # if for 100 loops no packages were received, raise connection loss
                    raise socket.error('Failed receiving data - connection loss')

                if print_steps:
                    print(f'\rreceiving [{len(data)}/{length}]')

            if print_steps:
                print(f'receiving took {time.time()-start} sec.')

            filename = resp['filename']

            i = 0
            if not overwrite:
                print("not overwriting")
                while os.path.isfile(filename):  # check if file with the same name already exists
                    i += 1
                    parts = filename.split('.')
                    filename = (parts[0].rstrip(str(i-1))+str(i)+'.')+'.'.join(parts[1::])

                if filename != resp['filename']:
                    print(f'renamed file from "{resp["filename"]}" to "{filename}"')

            if download_directory is not ...:
                filename = download_directory+'/'+filename

            with open(filename, 'wb') as out:
                out.write(data)
            client.send("done".encode())
        else:
            print(f'Cannot receive of type "{resp["type"]}"')

    elif mode in ('s', 'send'):
        file_content = open(filename, 'rb').read()

        length = struct.pack('>Q', len(file_content))

        msg = {
            "type": "file",
            "filename": filename.split('/')[-1]
        }

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((destination, 15151))  # connect to server

        server.sendall(json.dumps(msg).encode('utf-8'))
        server.recv(1024)
        server.sendall(length)
        server.sendall(file_content)
        resp = str()
        while resp != "done":
            resp = server.recv(1024).decode()
            if resp != "done":
                print(f"invalid response: {resp}")

    else:
        raise ValueError(f"invalid parameter 'mode' with value '{mode}'")
