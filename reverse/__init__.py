import requests
import config


def request_code(rule):
    r = requests.post(config.manage_url + "/create", data={"rule": rule})
    resp = r.json()
    if resp["success"]:
        return resp["message"]
    else:
        return ""


def check(token):
    r = requests.get(config.manage_url + "/get", params={"c": token})
    resp = r.json()
    if resp["success"]:
        if resp["message"]["requested"]:
            return True
    return False
