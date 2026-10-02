import os


class Req:
    def __init__(self, d):
        self.d = d


class Holder:
    def __init__(self):
        self.r = None


def fill(o):
    o.d = input()


def through_call():
    a = Req("ls")
    fill(a)
    os.system(a.d)


def through_field():
    a = Req("ls")
    h = Holder()
    h.r = a
    h.r.d = input()
    os.system(a.d)


def through_list():
    a = Req("ls")
    xs = [a]
    xs[0].d = input()
    os.system(a.d)


def through_identity_helper(a):
    return a


def through_identity():
    a = Req("ls")
    b = through_identity_helper(a)
    b.d = input()
    os.system(a.d)


def unrelated():
    a = Req("ls")
    b = Req("ls")
    b.d = input()
    os.system(a.d)
