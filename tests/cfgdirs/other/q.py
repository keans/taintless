import os
import myapp


def f(db):
    db.execute("select " + input())
    os.system(myapp.read())
