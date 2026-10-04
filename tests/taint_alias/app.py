import os as o
import hashlib as h
from os import system
from subprocess import run as r
from flask import request
def via_module_alias():
    o.system(request.args.get("c"))
def via_from_import():
    system(request.args.get("c"))
def via_renamed_import():
    r(request.args.get("c"), shell=True)
def crypto_through_alias():
    h.new(request.args.get("alg"))
def constant():
    o.system("ls")
