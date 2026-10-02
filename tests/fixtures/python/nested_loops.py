def grid(n):
    for i in range(n):
        for j in range(n):
            if i == j:
                continue
            if i + j > n:
                break
        else:
            print("no break", i)
    while n:
        n -= 1
    return n
