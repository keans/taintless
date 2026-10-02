def start():
    pass


def stop():
    pass


def other():
    pass


class Runner:
    def run(self):
        pass


class Worker:
    def run(self):
        pass


class Idle:
    def run(self):
        pass


COMMANDS = {"start": start, "stop": stop}


def dispatch(name):
    COMMANDS[name]()


def local_table(name):
    table = {"a": start}
    table["b"] = stop
    table[name]()


def appended(name):
    hooks = []
    hooks.append(start)
    hooks.append(stop)
    for h in hooks:
        h()


def objects():
    runners = [Runner(), Worker()]
    for r in runners:
        r.run()


def unknown_element(extra):
    hooks = [start]
    hooks.append(extra)
    hooks[0]()


class Bus:
    def __init__(self):
        self.listeners = []
        self.listeners.append(start)

    def emit(self):
        for fn in self.listeners:
            fn()


def keyed_dict():
    table = {"a": start, "b": stop}
    table["a"]()


def keyed_list():
    hs = [start, stop]
    hs[1]()


def appended_position():
    hs = [start]
    hs.append(stop)
    hs[0]()


def make_table():
    return {"a": start, "b": stop}


def returned():
    table = make_table()
    for h in table.values():
        h()


def run_all(hs):
    for h in hs:
        h()


def passes():
    run_all([start, other])


def items():
    for name, h in COMMANDS.items():
        h()


def fill(hs):
    hs.append(start)
    hs.append(stop)


def filled_in_place():
    hooks = []
    fill(hooks)
    for h in hooks:
        h()


def pair_key(table):
    for name, h in COMMANDS.items():
        name()


def computed_constant_key():
    table = {"a": start, "b": stop}
    key = "a"
    table[key]()


def computed_unknown_key(key):
    table = {"a": start, "b": stop}
    table[key]()
