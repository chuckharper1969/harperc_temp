#!/usr/bin/python

import requests
import json
import sys
import time

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

def hydrant_get_elk_mappings(hydrant_conn):
    mappings = [
        {
            "wf_id": "ABC001", 
            "elk_destination": "elk_ABC_destination"
        }, {
            "wf_id": "ABC002", 
            "elk_destination": "elk_ABC_destination"
        }, {
            "wf_id": "ABC003", 
            "elk_destination": "elk_ABC_destination"
        }, {
            "wf_id": "DEF001", 
            "elk_destination": "elk_DEF_destination"
        }, {
            "wf_id": "DEF005", 
            "elk_destination": "elk_DEF_destination"
        }
    ]

    return mappings

def cribl_auth(conn):
    username = conn["username"]
    password = conn["password"]
    cribl_url = conn["url"]

    auth_uri = '/api/v1/auth/login'
    # get logged in and grab a token
    header = {'accept': 'application/json', 'Content-Type': 'application/json'}
    login = '{"username": "' + username + '", "password": "' + password + '"}'
    r = requests.post(cribl_url+auth_uri,headers=header,data=login,verify=False)
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

def cribl_update_lookup(url, token, tmp_filename, lookup_name):
    json_obj = None

    headers = {
        'Accept': 'application/json', 
        'Authorization': 'Bearer ' + token 
    }
    json_data = {
        'id': lookup_name,
        'fileInfo': {
            'filename': '%s' % tmp_filename,
        },
    }

    cribl_uri = "%s/api/v1/system/lookups/%s" % (url, lookup_name)

    try:
        r = requests.patch(cribl_uri, headers=headers, json=json_data)
    except requests.exceptions.RequestException as e:
        print("ERROR: patch request %s [%s]" % (cribl_uri, str(e)))
        return json_obj
    
    if "Unauthorized" in r.text:
        print("ERROR: patch request %s [Invalid Token]" % (cribl_uri))
        return json_obj
    
    try:
        json_obj = json.loads(r.text)
    except:
        print("ERROR: put request %s [Invalid JSON returned]" % (cribl_uri))

    return json_obj

if __name__ == "__main__":

    cribl_conn = {
        "username": "admin",
        "password": "K33p0ut!",
        "url": "http://cribl.maejer.lab:9000"
    }

    hydrant_conn = {
        "username": "admin",
        "password": "K33p0ut!",
        "url": "http://hydrant.maejer.lab:9000"
    }

    lookup_name = "elk_destination_mapping.csv"
    lookup_dir = "./lookups"

    #
    # Create lookup file locally from hydrant mappings
    #
    mappings = hydrant_get_elk_mappings(hydrant_conn)
    
    f = open("%s/%s" % (lookup_dir, lookup_name), "w")
    # f.write("# %s\n" % time.time())
    f.write("wf_id,elk_destination\n")
    for x in range(len(mappings)):
        f.write("%s,%s\n" % (mappings[x]["wf_id"], mappings[x]["elk_destination"]))
    f.close()

    #
    # Upload local lookup to Cribl
    #
    cribl_auth_token = cribl_auth(cribl_conn)
    
    json_obj = cribl_upload_lookup(cribl_conn["url"], cribl_auth_token, lookup_dir, lookup_name)
    if json_obj == None or not "filename" in json_obj:
        sys.exit("Failed to upload file.")

    tmp_filename = json_obj["filename"]

    #
    # Update remote lookup file in Cribl
    #
    json_obj = cribl_update_lookup(cribl_conn["url"], cribl_auth_token, tmp_filename, lookup_name)
    print(json_obj)
    if json_obj == None or not "items" in json_obj:
        sys.exit("Failed to update file.")
    
    print("Success: %s" % json_obj)