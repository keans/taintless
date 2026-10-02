class Runner:
    def run(self):
        pass


class Other:
    def run(self):
        pass


class Svc:
    def __init__(self):
        self.runner = Runner()

    def go(self):
        self.runner.run()


class Holder:
    def __init__(self, svc):
        self.svc = Svc()

    def start(self):
        self.svc.runner.run()


def make() -> Runner:
    return Runner()


def main():
    r = make()
    r.run()
    s = Svc()
    s.go()
    t = r
    t.run()
