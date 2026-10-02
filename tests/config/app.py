import myapp


def f():
    d = myapp.read_request()
    myapp.db.raw_query(d)
    c = myapp.clean(d)
    myapp.db.raw_query(c)


def handler(data, other):
    myapp.db.raw_query(data)
    myapp.db.raw_query(other)
