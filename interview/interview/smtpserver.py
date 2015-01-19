#!/usr/bin/python2

import os
import sys
import string
import signal
import hashlib
import socket
import SocketServer

AUTHSERVER_SOCK = "/tmp/authserver.sock"
TMP_DIR = "/tmp/mails/"


class SMTPHandler(object):
    """
    Dumb as hell SMTP Server.
    Doesn't comply to RFC at all, just here to feed mailz for pop3ret...
    You're not expected to exploit it.
    """

    CRLF = "\r\n"
    hostname = '(none)'
    mailfrom = None
    mailto = set()
    data = None

    def read_until(self, stop, maxsize=1024 * 256):
        res = ''
        size = 0

        while not res.endswith(stop) and size < maxsize:
            res += sys.stdin.read(1)
            size += 1

        if size >= maxsize:
            raise Exception

        return res

    def read_line(self):
        return self.read_until(self.CRLF)

    def respond(self, txt):
        sys.stdout.write(txt + self.CRLF)
        sys.stdout.flush()

    def valid_mail(self, mail):
        charset = string.ascii_letters + string.digits + string.punctuation

        if not (mail.startswith('<') and mail.endswith('>')):
            return 0

        return all(c in charset for c in mail)

    def cmd_EHLO(self, line):
        if not any(line.startswith(cmd + " ") for cmd in ("HELO", "EHLO")):
            self.respond("503 Bad sequence of commands")
            return 1

        self.respond("250-%s Well ehlo there Mr. UPS man" % self.hostname)
        self.respond("250-8BITMIME")

        return 0

    def cmd_MAIL(self, line):
        line = line[10:]

        if self.valid_mail(line):
            self.mailfrom = line[1:-1]
            self.respond("250 OK")
        else:
            self.respond("501 Syntax: MAIL FROM:<user@address.tldr>")

    def cmd_RCPT(self, line):
        if not self.mailfrom:
            self.respond("503 Error: need MAIL command")
            return

        line = line[8:]

        if not self.valid_mail(line):
            self.respond("501 Syntax: RCPT TO:<user@address.tld>")
            return

        to = line[1:-1]

        try:
            user, host = to.rsplit('@')

            if not host == "insomni.hack":
                raise Exception

            charset = string.ascii_letters + string.digits

            if not all(c in charset for c in user):
                raise Exception

            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(AUTHSERVER_SOCK)
            sock.send("check_user:%s\n" % user)
            answer = sock.recv(1)
            sock.close()

            if answer != '\x01':
                raise Exception
        except:
            self.respond("550 No such user")
            return

        self.mailto.add(to)
        self.respond("250 OK")

    def cmd_DATA(self, line):
        if self.mailto == set():
            self.respond("554 no valid recipients")
            return

        self.respond("354 Start mail input; end with <CRLF>.<CRLF>")
        delimiter = self.CRLF + "." + self.CRLF
        data = self.read_until(delimiter)
        data = data[:-len(delimiter)]

        if not self.CRLF + self.CRLF in data:
            data = "From: %s%sTo: %s%s%s" % (self.mailfrom,
                                           self.CRLF,
                                           ', '.join(self.mailto),
                                           self.CRLF + self.CRLF,
                                           data)

        error = False

        for to in self.mailto:
            user = to.rsplit('@', 1)[0]

            try:
                try:
                    os.makedirs(TMP_DIR + user)
                except:
                    pass

                path = TMP_DIR + user + "/" + hashlib.sha256(data).hexdigest()
                if os.path.exists(path):
                    raise Exception

                f = open(path, "wb+")
                f.write(data)
                f.close()
            except:
                error = True

        if error:
            self.respond("451 Failed somehow")
        else:
            self.respond("250 OK")
            self.mailto.clear()
            self.mailfrom = None

    def handle(self):
        self.hostname = socket.gethostname()

        signal.alarm(60)

        self.respond("220 %s Simple Mail Transfer Service Ready" %
                     self.hostname)
        line = self.read_line().strip()

        if self.cmd_EHLO(line):
            return

        while True:
            line = self.read_line().strip()

            if line.startswith("MAIL FROM:"):
                self.cmd_MAIL(line)
            elif line.startswith("RCPT TO:"):
                self.cmd_RCPT(line)
            elif line == "DATA":
                self.cmd_DATA(line)
            elif line == "QUIT":
                self.respond("221 %s Service closing transmission channel" %
                             self.hostname)
                break
            else:
                self.respond("500 Syntax error, command unrecognized")


def main(argc, argv):
    smtp = SMTPHandler()
    smtp.handle()

if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
