import os


def dict_literal_clean():
    d = {"a": "ls", "b": input()}
    os.system(d["a"])


def dict_literal_tainted():
    d = {"a": "ls", "b": input()}
    os.system(d["b"])


def dict_write_later():
    d = {"a": "ls", "b": "ls"}
    d["b"] = input()
    os.system(d["a"])


def dict_dynamic_key_reads_all():
    d = {"a": "ls", "b": input()}
    k = input()
    os.system(d[k])


def dynamic_write_taints_all():
    d = {"a": "ls", "b": "ls"}
    k = "a"
    d[input()] = "x"
    os.system(d["a"])


def dynamic_value_write():
    d = {"a": "ls", "b": "ls"}
    k = os.environ["K"]
    d[k] = input()
    os.system(d["a"])


class Req:
    def __init__(self, d):
        self.d = d


def instances_apart():
    a = Req(input())
    b = Req("ls")
    os.system(b.d)


def instances_same():
    a = Req(input())
    b = Req("ls")
    os.system(a.d)


class Bare:
    pass


def unknown_class_instances_apart(make):
    a = make()
    b = make()
    a.cmd = input()
    os.system(b.cmd)


def unknown_class_same(make):
    a = make()
    a.cmd = input()
    os.system(a.cmd)
