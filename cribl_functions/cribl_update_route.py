#!/usr/bin/python

import requests
import json
import sys

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

def auth(leader_url,un,pw):
    auth_uri = '/api/v1/auth/login'
    # get logged in and grab a token
    header = {'accept': 'application/json', 'Content-Type': 'application/json'}
    login = '{"username": "' + un + '", "password": "' + pw + '"}'
    r = requests.post(leader_url+auth_uri,headers=header,data=login,verify=False)
    if (r.status_code == 200):
        res = r.json()
        return res["token"]
    else:
        print("Login failed, terminating")
        print(str(r.json()))
        sys.exit()

def cribl_get_routes(url, token):
    json_obj = None

    header = {
        'accept': 'application/json', 
        'Authorization': 'Bearer ' + token 
    }

    cribl_uri = "%s/api/v1/routes" % url

    try:
        r = requests.get(cribl_uri, headers=header, verify=False)
    except requests.exceptions.RequestException as e:
        print("ERROR: get request %s [%s]" % (cribl_uri, str(e)))
        return json_obj
    
    if "Unauthorized" in r.text:
        print("ERROR: get request %s [Invalid Token]" % (cribl_uri))
        return json_obj

    try:
        json_obj = json.loads(r.text)
    except:
        print("ERROR: get request %s [Invalid JSON returned]" % (cribl_uri))
        return json_obj

    return json_obj

def cribl_get_route_by_id(url, token, item_id):
    json_obj = None

    header = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token 
    }

    cribl_uri = "%s/api/v1/routes/%s" % (url, item_id)

    try:
        r = requests.get(cribl_uri, headers=header, verify=False)
    except requests.exceptions.RequestException as e:
        print("ERROR: get request %s [%s]" % (cribl_uri, str(e)))
        return json_obj
    
    if "Unauthorized" in r.text:
        print("ERROR: get request %s [Invalid Token]" % (cribl_uri))
        return json_obj

    try:
        json_obj = json.loads(r.text)
    except:
        print("ERROR: get request %s [Invalid JSON returned]" % (cribl_uri))
        return json_obj

    return json_obj

def cribl_update_route(url, token, item_id, route_obj):
    json_obj = None

    header = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token 
    }

    cribl_uri = "%s/api/v1/routes/%s" % (url, item_id)

    try:
        r = requests.patch(cribl_uri, headers=header, json=route_obj, verify=False)
    except requests.exceptions.RequestException as e:
        print("ERROR: get request %s [%s]" % (cribl_uri, str(e)))
        return json_obj
    
    if "Unauthorized" in r.text:
        print("ERROR: get request %s [Invalid Token]" % (cribl_uri))
        return json_obj

    try:
        json_obj = json.loads(r.text)
    except:
        print("ERROR: get request %s [Invalid JSON returned]" % (cribl_uri))
        return json_obj

    return json_obj

if __name__ == "__main__":

    username = "admin"
    password = "K33p0ut!"
    cribl_api_url = "http://cribl.maejer.lab:9000"

    # 
    item_target_id = "default"
    route_target_name = "cribl_to_elk_route"

    cribl_auth_token = auth(cribl_api_url, username, password)
    
    # this should be called get routes by group name. Think it has something
    # to do with seperating worker groups
    json_obj = cribl_get_route_by_id(cribl_api_url, cribl_auth_token, item_target_id)
    print(json_obj)
    sys.exit()
    if json_obj == None or not json_obj["count"] == "1":
        print("Failed")

    route_obj = json_obj["items"][0]
    route_order = None

    for j in range(len(route_obj["routes"])):

        if not route_obj["routes"][j]["name"] == route_target_name:
            continue

        route_order = j

    print("name:", route_obj["routes"][route_order]["name"])
    print("filter:", route_obj["routes"][route_order]["filter"])

    route_obj["routes"][route_order]["filter"] = "__inputId=='splunk_hec:splunk_HEC_8088' && (app_id=='app01' || app_id=='app02')"

    print(route_obj)

    update_obj = cribl_update_route(cribl_api_url, cribl_auth_token, item_target_id, route_obj)
    print()
    print(update_obj)

    