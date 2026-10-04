import requests, ssl
def f(u):
    requests.get(u, verify=False)
    requests.get(u, verify=True)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # verify=False  (a comment is not a finding)
