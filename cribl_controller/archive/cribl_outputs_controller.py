#!/usr/bin/python

import requests
import json
import sys
import re

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

def hydrant_get_elk_destinations(hydrant_conn):
    # destinations = [
    #     {
    #         "label": "elk_ABC_destination",
    #         "url": "http://192.168.10.254:9000/_bulk",
    #         "token": "12345-ABCD-78901-HIJKL"
    #     }, {
    #         "label": "elk_DEF_destination",
    #         "url": "http://192.168.10.254:9000/_bulk",
    #         "token": "12345-ABCD-78901-HIJKL"
    #     }, {
    #         "label": "elk_GHI_destination",
    #         "url": "http://192.168.10.254:9000/_bulk",
    #         "token": "12345-ABCD-78901-HIJKL"
    #     }, {
    #         "label": "elk_JKL_destination",
    #         "url": "http://192.168.10.254:9000/_bulk",
    #         "token": "12345-ABCD-78901-HIJKL"
    #     }
    # ]

    destinations = {
        "elk_abc_destination": {
            "label": "elk_ABC_destination",
            "url": "http://192.168.10.254:9000/_bulk",
            "token": "12345-ABCD-78901-HIJKL"
        },
        "elk_def_destination": {
            "label": "elk_DEF_destination",
            "url": "http://192.168.10.254:9000/_bulk",
            "token": "12345-ABCD-78901-HIJKL"
        },
        "elk_ghi_destination": {
            "label": "elk_GHI_destination",
            "url": "http://192.168.10.254:9000/_bulk",
            "token": "12345-ABCD-78901-HIJKL"
        },
        "elk_jkl_destination": {
            "label": "elk_JKL_destination",
            "url": "http://192.168.10.254:9000/_bulk",
            "token": "12345-ABCD-78901-HIJKL"
        }
    }

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

    cribl_auth_token = auth(cribl_conn)
    cribl_conn["token"] = cribl_auth_token

    outputs_deleted = []
    outputs_added = []

    cribl_output_items = cribl_get_outputs(cribl_conn)
    cribl_outputs = {}
    for output in cribl_output_items["items"]:
        if not output["id"].startswith("elk_destination"):
            continue
        cribl_outputs[output["id"].lower()] = output
        outputs_added.append(output["id"].lower())
    elk_outputs = hydrant_get_elk_destinations(hydrant_conn)

    for elk_output in elk_outputs:
        if elk_output not in cribl_outputs:

            cribl_add_elk_output(cribl_conn, elk_outputs[elk_output])
    
    cribl_elk_router_output = None
    for cribl_output in cribl_outputs:
        if cribl_output == "ELK_Outputs_Router".lower():
            cribl_elk_router_output = cribl_outputs[cribl_output]
            continue
        if not cribl_output.startswith("elk_destination"):
            continue
        if cribl_output not in elk_outputs:
            outputs_deleted.append(cribl_outputs[cribl_output]["id"].lower())
            cribl_del_output(cribl_conn, cribl_outputs[cribl_output])
        
    print(cribl_elk_router_output)
    configured_rules = {}
    for rule in cribl_elk_router_output["rules"]:
        filter = rule["filter"]
        print(filter)
        m = re.search('^elk_destination==\'(.*)\'$', filter)
        if not m:
            continue
        elk_destination = m[1]

    print("DELETED: ", outputs_deleted)
    print("ADDED:", outputs_added)
    