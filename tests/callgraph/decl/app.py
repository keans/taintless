def make():
    return None


class Runner:
    def run(self):
        pass


class Other:
    def run(self):
        pass


class Svc:
    r: Runner

    def go(self):
        self.r.run()

    def local(self):
        x: Runner = make()
        x.run()
