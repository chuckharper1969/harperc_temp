#!/usr/bin/python

import requests
import json
import sys
import re

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

def hydrant_get_elk_destinations(hydrant_conn):
    destinations = [
        {
            "label": "elk_ABC_destination",
            "url": "http://192.168.10.254:9000/_bulk",
            "index": "cluster1",
            "token": "12345-ABCD-78901-HIJKL",
            "token_changed": True
        }, {
            "label": "elk_DEF_destination",
            "url": "http://192.168.10.254:9000/_bulk",
            "index": "cluster2",
            "token": "12345-ABCD-78901-HIJKL",
            "token_changed": False
        }, {
            "label": "elk_GHI_destination",
            "url": "http://192.168.10.254:9000/_bulk",
            "index": "cluster3",
            "token": "12345-ABCD-78901-HIJKL",
            "token_changed": False
        }, {
            "label": "elk_JKL_destination",
            "url": "http://192.168.10.254:9000/_bulk",
            "index": "cluster4",
            "token": "12345-ABCD-78901-HIJKL",
            "token_changed": False
        }
    ]

    return destinations

def auth(cribl_conn):
    header = {
        'Accept': 'application/json', 
        'Content-Type': 'application/json'
    }
    data =  {
        "username": cribl_conn["username"],
        "password": cribl_conn["password"]
    }

    cribl_uri = cribl_conn["url"] + '/api/v1/auth/login'
    r = requests.post(cribl_uri, headers=header, json=data, verify=False)
    if (r.status_code == 200):
        res = r.json()
        return res["token"]
    else:
        print("Login failed, terminating")
        print(str(r.json()))
        sys.exit()

def cribl_get_outputs(cribl_conn):

    header = {
        'accept': 'application/json', 
        'Content-Type': 'application/json', 
        'Authorization': 'Bearer ' + cribl_conn["token"] 
    }

    cribl_uri = "%s/api/v1/system/outputs" % cribl_conn["url"]

    try:
        r = requests.get(cribl_uri, headers=header, verify=False)
    except requests.exceptions.RequestException as e:
        print("ERROR: get request %s [%s]" % (cribl_uri, str(e)))
        sys.exit()
    
    if (r.status_code != 200):
        print("/api/v1/system/outputs failed, terminating")
        print(str(r.json()))
        sys.exit()

    return r.json()

def cribl_add_elk_output(cribl_conn, elk_output):
    print("ADDING %s." % elk_output["label"])

def cribl_del_output(cribl_conn, cribl_output):
    print("REMOVING %s." % cribl_output["id"])

def load_json_file(file_path):

    try:
        f = open(file_path)
    except Exception as e:
        raise("Failed opening new_elk_output json file [%s]" % str(e))
    
    json_obj = json.load(f)

    f.close()

    return(json_obj)

if __name__ == "__main__":

    #
    # READ JSON FILE
    #
    config = load_json_file("config.json")

    #
    # READ New ELK Output template file
    #
    new_elk_output = load_json_file(config["new_elk_output_file"])

    #
    # Get Cribl Token
    #
    cribl_auth_token = auth(config["cribl_conn"])
    config["cribl_conn"]["token"] = cribl_auth_token

    changes_made = False

    #
    # GET /api/v1/system/outputs
    # { 'items': [OUTPUTSLIST] } 
    #
    cribl_output_items = cribl_get_outputs(config["cribl_conn"])

    #
    # LIST { 'id': 'OUTPUTNAME', etc } } 
    #
    cribl_outputs_tmp = cribl_output_items["items"]

    #
    # Remove outputs that are out of scope
    #
    elk_outputs_router = None
    cribl_outputs = []
    for cribl_output in cribl_outputs_tmp:
        # capture elk_output_router
        if cribl_output["id"] == config["elk_output_router"]:
            elk_outputs_router = cribl_output
            continue
        # continue unless output begins with elk prefix
        if not cribl_output["id"].startswith(config["elk_output_prefix"]):
            continue

        cribl_outputs.append(cribl_output)

    #
    # LIST { label: :ABEL, url:URL, token:TOKEN }
    #
    elk_definitions = hydrant_get_elk_destinations(config["hydrant_conn"])

    #
    # Loop through ELK definitions to determine if new Cribl outputs 
    # need to be added or modified
    #
    for elk_def in elk_definitions:
        # check label against existing Cribl outputs
        output_found = False
        update_required = False
        for cribl_output in cribl_outputs:
            updated_output = cribl_output
            updated_output["url"] = elk_def["url"]
            updated_output["index"] = elk_def["index"]
            updated_output["index"] = elk_def["index"]
        for cribl_output in cribl_outputs:
            if elk_def["label"] == cribl_output["id"]:
                output_found = True
                if elk_def["url"] != cribl_output["url"]:
                    update_required = True


        # label does not exist in outputs
        if output_found == True:
            continue

    

    