import os


class Job:
    def __init__(self, cmd):
        self.cmd = cmd
        self.name = "job"

    def run(self):
        os.system(self.cmd)
        print(self.name)


def main(user):
    j = Job(user)
    j.run()
    x = user
    x = "safe"
    print(x)


def alias(user):
    a = Job("ls")
    b = a
    b.cmd = user
    os.system(a.cmd)


def apply(f, v):
    return f(v)


def shout(s):
    return s + "!"


def callback(user):
    return apply(shout, user)


def method_on_var(user):
    j = Job(user)
    j.run()
