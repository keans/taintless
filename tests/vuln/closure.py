import os


def run():
    cmd = input()
    go = lambda: os.system(cmd)
    go()
