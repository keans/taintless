import os


def leak():
    secret = input()
    cmd = "ls"
    if secret == "yes":
        cmd = "id"
    os.system(cmd)


def nested():
    secret = input()
    cmd = "ls"
    if secret:
        if len(secret) > 3:
            cmd = "id"
    os.system(cmd)


def via_param(flag):
    cmd = "ls"
    if flag:
        cmd = "id"
    return cmd


def caller():
    os.system(via_param(input()))


def loop():
    secret = input()
    cmd = "ls"
    while secret:
        cmd = "id"
        break
    os.system(cmd)


def clean():
    secret = "x"
    cmd = "ls"
    if secret == "yes":
        cmd = "id"
    os.system(cmd)
