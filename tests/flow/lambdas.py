import os


def run(user):
    list(map(lambda v: os.system(v), [user]))
    f = lambda w: w + "!"
    return f(user)
