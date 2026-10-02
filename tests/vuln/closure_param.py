import os


def run(cmd):
    go = lambda: os.system(cmd)
    go()


def main():
    run(input())
