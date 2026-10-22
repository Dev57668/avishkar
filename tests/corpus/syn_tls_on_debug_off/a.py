import requests

def get(u):
    return requests.get(u, verify=True)

DEBUG_FLAG = False
app.run(debug=False)
