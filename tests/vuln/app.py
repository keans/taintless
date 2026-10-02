import os
import pickle
import subprocess
import hashlib
from flask import request


def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
    subprocess.run("ls " + cmd, shell=True)
    safe = int(request.args.get("n"))
    os.system("echo %d" % safe)


def db(conn):
    name = input()
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE n = '" + name + "'")
    cur.execute("SELECT * FROM t WHERE n = ?", (name,))


def branches(flag):
    data = input()
    if flag:
        data = "constant"
    os.system(data)


def overwritten():
    x = input()
    x = "ls"
    os.system(x)


def always():
    eval("1+1")
    pickle.loads(b"..")
    hashlib.md5(b"x")


def dead():
    return 1
    os.system("never")


def loops():
    for a in os.environ.get("PATHS", "").split(":"):
        os.system(a)


def comprehension():
    names = [n.strip() for n in input().split(",")]
    for n in names:
        os.system(n)
