def f(xs, a, b):
    ys = [x * 2 for x in xs if x > 0 if x < 10]
    z = a if b else None
    ok = a and b()
    match a:
        case 1 if b:
            return 1
        case 2 | 3:
            return 2
        case _:
            return 0
    return ys, z, ok
