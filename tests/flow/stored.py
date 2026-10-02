import os


def run(cmd):
    os.system(cmd)


def log(msg):
    print(msg)


HANDLERS = {"run": run}
QUEUE = []
QUEUE.append(run)


def registry(user):
    HANDLERS["run"](user)


def queue(user):
    for h in QUEUE:
        h(user)


class Bus:
    def __init__(self):
        self.cb = run
        self.subs = []
        self.subs.append(run)

    def fire(self, x):
        self.cb(x)

    def fire_all(self, x):
        for s in self.subs:
            s(x)


def reassigned(user):
    f = log
    f = run
    f(user)


def rebound_away(user):
    f = run
    f = log
    f(user)


def local_table(user):
    t = {}
    t["go"] = run
    t["go"](user)


def passed(user):
    cbs = [run]
    map(cbs[0], [user])
