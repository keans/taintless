import os


class Runner:
    def run(self):
        os.system(self.cmd)

    def get(self):
        return self.cmd

    def set(self, c):
        self.cmd = c


def recv_field():
    r = Runner()
    r.cmd = input()
    r.run()


def recv_return():
    r = Runner()
    r.cmd = input()
    os.system(r.get())


def via_setter():
    r = Runner()
    r.set(input())
    r.run()


def make(c):
    r = Runner()
    r.set(c)
    return r


def via_factory():
    r = make(input())
    r.run()


def sink(x):
    os.system(x)


def apply(fn, x):
    fn(x)


def apply_ret(fn, x):
    return fn(x)


def ho_named():
    apply(sink, input())


def ho_lambda():
    apply(lambda v: os.system(v), input())


def ho_ret():
    os.system(apply_ret(lambda v: v + "x", input()))


def clean_cb():
    apply(print, input())
