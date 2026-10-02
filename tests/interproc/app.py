import os
from flask import request
from util import build, constant, nested, read_input, recur, run_cmd, safe


def main():
    data = request.args.get("q")
    run_cmd(data)
    os.system(build(data))
    x = read_input()
    os.system(x)
    os.system(safe(data))
    os.system(constant(data))
    nested(data)
    run_cmd("ls")
    y = recur(3, "")
    os.system(y)
