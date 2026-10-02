import os


class Job:
    def __init__(self, cmd, safe):
        self.cmd = cmd
        self.safe = safe
        self.label = "x"

    def run(self):
        os.system(self.cmd)
        os.system(self.safe)
        os.system(self.label)


def main():
    Job(input(), "ls").run()


class Req:
    def load(self):
        self.data = input()

    def use(self):
        os.system(self.data)
        os.system(self.other)


class Local:
    def go(self):
        self.a = input()
        self.b = "ls"
        os.system(self.b)
        os.system(self.a)
        self.a = "clean now"
        os.system(self.a)
