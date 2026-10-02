import os


def run_cmd(cmd):
    os.system(cmd)


def build(name):
    return "ls " + name


def read_input():
    return input()


def safe(x):
    return int(x)


def constant(x):
    return "ls"


def nested(c):
    run_cmd(c)


def recur(n, acc):
    if n == 0:
        return acc
    return recur(n - 1, acc + input())
