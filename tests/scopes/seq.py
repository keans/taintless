class A:
    def run(self): pass


class B:
    def run(self): pass


def sequence():
    x = A()
    x.run()
    x = B()
    x.run()


def branches(c):
    if c:
        x = A()
    else:
        x = B()
    x.run()


def loop_changes_it():
    x = A()
    for _ in range(2):
        x.run()
        x = B()
