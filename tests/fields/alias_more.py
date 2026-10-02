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


def list_append_is_not_a_field_write():
    a = Req("ls")
    xs = [a]
    xs.append(input())
    os.system(a.d)


def other_element_stays_clean():
    a = Req("ls")
    b = Req("ls")
    xs = [a, b]
    xs[0].d = input()
    os.system(b.d)


def same_element_is_tainted():
    a = Req("ls")
    b = Req("ls")
    xs = [a, b]
    xs[1].d = input()
    os.system(b.d)


def through_return(a):
    return a


def through_identity():
    a = Req("ls")
    b = through_return(a)
    b.d = input()
    os.system(a.d)


def clean_control():
    a = Req("ls")
    b = Req("ls")
    b.d = input()
    os.system(a.d)
