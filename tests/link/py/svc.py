from types import R, T, U


def via_alias(a: R):
    a.run()


def via_annotated(a: T):
    a.run()


def via_statement(a: U):
    a.run()
