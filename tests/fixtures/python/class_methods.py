class A:
    def one(self):
        def inner():
            return 1
        return inner()

    def two(self):
        with open("f") as fh:
            fh.read()
