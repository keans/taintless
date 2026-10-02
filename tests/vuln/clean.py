import shlex
import subprocess


def tidy(name):
    n = int(input())
    subprocess.run(["ls", shlex.quote(name)])
    return n
