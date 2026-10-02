import os


def helper():
    pass


def register(cb):
    cb()


def wire():
    register(helper)
    f = helper
    f()


class Base:
    def run(self):
        self.step()

    def step(self):
        pass


class Child(Base):
    def step(self):
        os.system(input())


class Other(Base):
    def run(self):
        super().run()


def use(b: Base):
    b.step()
