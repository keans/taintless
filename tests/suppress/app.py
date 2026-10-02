import os


def a():
    os.system(input())  # taintless: ignore


def b():
    # taintless: ignore[command-injection]
    os.system(input())


def c():
    os.system(input())  # taintless: ignore[sql-injection]


def d():
    os.system(input())


def e():
    # taintless: ignore
    x = 1
    os.system(input())
