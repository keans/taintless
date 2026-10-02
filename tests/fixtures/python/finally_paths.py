def f(x):
    try:
        if x:
            return 1
        raise ValueError("bad")
    except ValueError:
        raise
    finally:
        cleanup()


def g(items):
    for it in items:
        try:
            if it:
                break
            continue
        finally:
            release(it)
