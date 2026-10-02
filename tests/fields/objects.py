import os


class Req:
    def __init__(self, d):
        self.d = d

    def run(self):
        os.system(self.d)


def tainted():
    r = Req(input())
    os.system(r.d)
    r.run()


def clean():
    r = Req("ls")
    os.system(r.d)


def copied():
    r = Req(input())
    s = r
    os.system(s.d)


def overwritten():
    r = Req(input())
    r.d = "ls"
    os.system(r.d)


class Runner:
    def go(self, cmd):
        os.system(cmd)


def typed_call():
    rn = Runner()
    rn.go(input())
