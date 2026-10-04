from flask import request
import myapp
def run():
    myapp.lookup(table="users", q=request.args["q"])
    myapp.lookup(table=request.args["t"], q="fixed")
