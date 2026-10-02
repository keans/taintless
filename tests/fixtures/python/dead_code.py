def early(x):
    if x:
        return 1
        print("unreachable")
    return 2
    print("also unreachable")
