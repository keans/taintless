import os


def run(user, flag):
    cmd = "ls"
    if flag > 0:
        cmd = user
    while user:
        os.system(cmd)
    return cmd
