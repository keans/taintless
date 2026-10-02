def f(xs):
    total = 0
    for x in xs:
        if x < 0:
            continue
        elif x > 100:
            break
        else:
            total += x
    try:
        eval(str(total))
    except ValueError:
        return -1
    finally:
        print("done")
    return total
