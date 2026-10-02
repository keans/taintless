import os


def writes():
    cmd = ""

    def load():
        nonlocal cmd
        cmd = input()

    load()
    os.system(cmd)


def local_only():
    cmd = ""

    def load():
        cmd = input()
        return cmd

    load()
    os.system(cmd)


def from_param(arg):
    out = ""

    def store(v):
        nonlocal out
        out = v

    store(arg)
    os.system(out)


def feed():
    from_param(input())
