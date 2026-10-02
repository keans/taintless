import os


def run(cmd):
    os.system(cmd)


def log(msg):
    print(msg)


HANDLERS = {"run": run, "log": log}
QUEUE = []
QUEUE.append(run)


def dispatch(name):
    HANDLERS[name](input())


def drain():
    for h in QUEUE:
        h(input())


class Bus:
    def __init__(self):
        self.cb = run
        self.safe = log
        self.subs = []
        self.subs.append(run)

    def fire(self, x):
        self.cb(x)

    def fire_safe(self, x):
        self.safe(x)

    def fire_all(self, x):
        for s in self.subs:
            s(x)


def use_bus():
    b = Bus()
    b.fire(input())


def local_table():
    table = {}
    table["go"] = run
    table["go"](input())


def local_alias():
    f = run
    f(input())


def only_log():
    h = log
    h(input())
