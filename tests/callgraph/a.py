from b import helper


def main():
    helper()
    local()
    fact(3)


def local():
    helper()


def fact(n):
    return n * fact(n - 1)


def unused():
    print("x")
