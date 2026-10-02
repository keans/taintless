# taintless: ignore-file[command-injection]
import os


def f():
    os.system(input())
