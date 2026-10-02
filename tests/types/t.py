import os


class Runner:
    def go(self, cmd):
        os.system(cmd)


class Safe:
    def go(self, cmd):
        print(cmd)


def make() -> Runner:
    return Runner()


def make_safe() -> Safe:
    return Safe()


def via_factory():
    r = make()
    r.go(input())


def via_safe():
    s = make_safe()
    s.go(input())


def via_param(r: Runner):
    r.go(input())
