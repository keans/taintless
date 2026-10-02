def m(cmd):
    match cmd:
        case "go":
            return 1
        case "stop" if cmd:
            return 2
        case _:
            return 0
