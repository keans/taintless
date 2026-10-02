import os


class Req:
    def __init__(self, d):
        self.d = d


def write_through():
    a = Req("ls")
    b = a
    b.d = input()
    os.system(a.d)


def rebound():
    a = Req("ls")
    b = a
    b = Req("ls")
    b.d = input()
    os.system(a.d)


def overwritten_through_alias():
    a = Req(input())
    b = a
    b.d = "ls"
    os.system(a.d)


def one_branch(flag):
    a = Req("ls")
    b = a
    if flag:
        b = Req("ls")
    b.d = input()
    os.system(a.d)
