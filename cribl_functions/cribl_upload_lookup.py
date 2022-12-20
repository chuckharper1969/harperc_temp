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

def cribl_upload_lookup(url, token, lookup_dir, lookup_name):
    json_obj = None

    headers = {
        'Content-Type': 'text/csv', 
        'Authorization': 'Bearer ' + token 
    }
    params = {
        'filename': lookup_name,
    }

    cribl_uri = "%s/api/v1/system/lookups" % url

    file_path = "%s/%s" % (lookup_dir, lookup_name)
    with open(file_path, 'rb') as f:
        data = f.read()

    try:
        r = requests.put(cribl_uri, params=params, headers=headers, data=data)
    except requests.exceptions.RequestException as e:
        print("ERROR: put request %s [%s]" % (cribl_uri, str(e)))
        return json_obj
    
    if "Unauthorized" in r.text:
        print("ERROR: put request %s [Invalid Token]" % (cribl_uri))
        return json_obj
    
    try:
        json_obj = json.loads(r.text)
    except:
        print("ERROR: put request %s [Invalid JSON returned]" % (cribl_uri))
        return json_obj

    return json_obj

if __name__ == "__main__":

    username = "admin"
    password = "K33p0ut!"
    cribl_api_url = "http://cribl.maejer.lab:9000"

    lookup_name = "test2.csv"
    lookup_dir = "./lookups"

    cribl_auth_token = auth(cribl_api_url, username, password)
    
    json_obj = cribl_upload_lookup(cribl_api_url, cribl_auth_token, lookup_dir, lookup_name)
    if json_obj == None or not "filename" in json_obj:
        sys.exit("Failed to upload file.")
    
    print("Success: %s" % json_obj)