#!/usr/bin/env python2

from SocketServer import *
import hashlib
import socket
import stat
import os

UNIX_SOCK_PATH = "/tmp/authserver.sock"
AUTHFILE_PATH = "chall_users.txt"

try:
    os.remove(UNIX_SOCK_PATH)
except:
    pass

try:
    os.system("mkdir /tmp/mails/ && chown -r mails")
except:
    pass

class ThreadedUnixRequestHandler(BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024).strip()

        authfile = open(AUTHFILE_PATH, "r")
        lines = authfile.read().split("\n")

        if not data or data == '':
		return

        if data.startswith("check_user:"):
            user = data[len("check_user:"):]

            for line in lines:
                if len(line) < 10: # sometimes the line is just ':'
                    continue

                cur_usr, cur_pwd = line.split(':')

                if cur_usr == user:
                    self.request.sendall("\x01")
                    return
        elif data.startswith("check_auth:"):
            nothing, user, secret, password = data.split(':')

            for line in lines:
                if len(line) < 10: # sometimes the line is just ':'
                    continue

                cur_usr, cur_pwd = line.split(':')
                cur_pwd = hashlib.md5(secret + cur_pwd).hexdigest()

                if cur_usr == user and cur_pwd == password:
                    print '[+] Authentication succeed'
                    self.request.sendall("\x01")
                    return

        print '[-] Authentication failed'
        self.request.sendall("\x00")

if __name__ == "__main__":
    server = ThreadingUnixStreamServer(UNIX_SOCK_PATH, ThreadedUnixRequestHandler)

    # meh.
    os.chmod(UNIX_SOCK_PATH, stat.S_IFSOCK | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
             stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP |
             stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)

    server.serve_forever()
