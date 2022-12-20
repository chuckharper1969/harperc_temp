#!/usr/bin/python

import requests
import json
import sys
import re

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

# {
#     "label": "elk_destination_ABC",
#     "url": "http://elk:9200/_bulkxxx",
#     "username": "USERNAME",
#     "password": "PASSWORDXXX"
# }
def hydrant_get_elk_destinations(url, username, password):
    destinations = [
        {
            "label": "elk_destination_ABC",
            "url": "http://elk:9200/_bulkxxx",
            "username": "USERNAME",
            "password": "PASSWORDXXX"
        },{
            "label": "elk_destination_DEF",
            "url": "http://elk:9200/_bulkxxx",
            "username": "USERNAME",
            "password": "PASSWORDXXX"
        },{
            "label": "elk_destination_GHI",
            "url": "http://elk:9200/_bulkxxx",
            "username": "USERNAME",
            "password": "PASSWORDXXX"
        }
    ]

    return destinations

##############################################################################
# Cribl Auth
##############################################################################
def auth(cribl_url, cribl_username, cribl_password):
    header = {
        'Accept': 'application/json', 
        'Content-Type': 'application/json'
    }
    data =  {
        "username": cribl_username,
        "password": cribl_password
    }

    endpoint = "api/v1/auth/login"
    cribl_uri = "%s/%s" % (cribl_url, endpoint)

    try:
        r = requests.post(cribl_uri, headers=header, json=data, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        sys.exit("ERROR: %s" % str(e))

    return r.json()["token"]


##############################################################################
# cribl_get_outputs
##############################################################################
def cribl_get_outputs(cribl_url, cribl_token):

    header = {
        'Accept': 'application/json', 
        'Authorization': 'Bearer ' + cribl_token 
    }

    endpoint = "api/v1/system/outputs"
    cribl_uri = "%s/%s" % (cribl_url, endpoint)

    try:
        r = requests.get(cribl_uri, headers=header, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        sys.exit("ERROR: %s" % str(e))
    
    return r.json()

##############################################################################
# cribl_update_destination
##############################################################################
def cribl_update_destination(cribl_url, cribl_auth_token, output_id, json_output):
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + cribl_auth_token
    }

    endpoint = "api/v1/system/outputs"
    cribl_uri = "%s/%s/%s" % (cribl_url, endpoint, output_id)

    try:
        r = requests.patch(cribl_uri, headers=headers, json=json_output, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        sys.exit("ERROR: %s" % str(e))

    return r.json()

##############################################################################
# cribl_delete_destination
##############################################################################
def cribl_delete_destination(cribl_url, cribl_auth_token, output_id):
    headers = {
        'Accept': 'application/json', 
        'Authorization': 'Bearer ' + cribl_auth_token 
    }

    endpoint = "api/v1/system/outputs"
    cribl_uri = "%s/%s/%s" % (cribl_url, endpoint, output_id)

    try:
        r = requests.delete(cribl_uri, headers=headers, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        sys.exit("ERROR: %s" % str(e))
    
    return r.json()

##############################################################################
# cribl_add_destination
##############################################################################
def cribl_add_destination(cribl_url, cribl_auth_token, json_new_output):

    headers = {
        'Accept': 'application/json', 
        'Authorization': 'Bearer ' + cribl_auth_token 
    }

    endpoint = "api/v1/system/outputs"
    cribl_uri = "%s/%s" % (cribl_url, endpoint)

    try:
        r = requests.post(cribl_uri, headers=headers, json=json_new_output, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        sys.exit("ERROR: %s" % str(e))

    return r.json()

##############################################################################
# find_rule_index
##############################################################################
def find_rule_index(json_elk_output_router, output_id):
    index_found = -1
    for x in range(len(json_elk_output_router["rules"])):
        if "'%s'" % output_id in json_elk_output_router["rules"][x]["filter"]:
            index_found = x
    return index_found

##############################################################################
# load_json_file
##############################################################################
def load_json_file(file_path):

    try:
        f = open(file_path)
    except Exception as e:
        raise("Failed opening new_elk_output json file [%s]" % str(e))
    
    json_obj = json.load(f)

    f.close()

    return(json_obj)

##############################################################################
# main
##############################################################################
def main():

    ###########################################################################
    # CONFIGURATION
    ###########################################################################
    json_config = load_json_file("config.json")

    cribl_url = json_config["cribl_conn"]["url"]
    cribl_username = json_config["cribl_conn"]["username"]
    cribl_password = json_config["cribl_conn"]["password"]

    hydrant_url = json_config["hydrant_conn"]["url"]
    hydrant_username = json_config["hydrant_conn"]["username"]
    hydrant_password = json_config["hydrant_conn"]["password"]

    json_elk_output_router = None
    elk_output_router_name = json_config["elk_output_router_name"]
    elk_output_prefix = json_config["elk_output_prefix"]

    json_elk_output_json_template = load_json_file(json_config["elk_output_json_template"])
    json_elk_secrets_json = load_json_file(json_config["elk_secrets_json_file"])

    ###########################################################################
    # Get Cribl Token
    ###########################################################################
    cribl_auth_token = auth(cribl_url, cribl_username, cribl_password)

    ###########################################################################
    # Get List of outputs from Cribl
    # GET /api/v1/system/outputs
    ###########################################################################
    cribl_elk_outputs = []
    cribl_output_items = cribl_get_outputs(cribl_url, cribl_auth_token)
    cribl_outputs = cribl_output_items["items"]
    
    for cribl_output in cribl_outputs:
        # capture json_elk_output_router
        if cribl_output["id"] == elk_output_router_name:
            json_elk_output_router = cribl_output
            continue
        # continue unless output begins with elk prefix
        if not cribl_output["id"].startswith(elk_output_prefix):
            continue

        cribl_elk_outputs.append(cribl_output)

    ###########################################################################
    # Get list of ELK definitions from Hydrant
    ###########################################################################
    elk_definitions = hydrant_get_elk_destinations(hydrant_url, hydrant_username, hydrant_password)

    ###########################################################################
    # ADD new outputs from ELK defs that are not already in Cribl
    # OUTPUTS have to be added first before rules can be assigned to router
    ###########################################################################
    for elk_def in elk_definitions:

        found = False
        for cribl_output in cribl_elk_outputs:
            if cribl_output["id"] == elk_def["label"]:
                found = True
        if found == True:
            continue

        json_new_output = json_elk_output_json_template
        json_new_output["id"] = elk_def["label"]
        json_new_output["url"] = elk_def["url"]
        json_new_output["auth"]["username"] = elk_def["username"]
        json_new_output["auth"]["password"] = elk_def["password"]

        #
        # ADD NEW OUTPUT
        #
        res = cribl_add_destination(cribl_url, cribl_auth_token, json_new_output)

    ###########################################################################
    # Update rules in Output Router if neccessary
    # Rules have to be removed first before Cribl Destinations can be DELETED
    ###########################################################################
    rules = {}
    for rule in json_elk_output_router["rules"]:
        m = re.search('^elk_destination==\'(.*)\'$', rule["filter"])
        if not m:
            continue
        rule_id = m[1]
        rules[rule_id] = rule["output"]
    
    update_required = False
    # check if any rules need to be added
    for elk_def in elk_definitions:
        if not elk_def["label"] in rules:
            rules[elk_def["label"]] = elk_def["label"]
            update_required = True
            continue
        # check if output value is up to date in rules
        if rules[elk_def["label"]] != elk_def["label"]:
            update_required = True

    # check if any rules need to be deleted
    delete_keys = []
    for key in rules:
        found = False
        if key == "NO_ELK_DESTINATIONS":
            continue
        for elk_def in elk_definitions:
            if elk_def["label"] == key:
                found = True
        if found == False:
            update_required = True
            delete_keys.append(key)
    
    # rebuild rules list and update in cribl
    if update_required == True:

        print("Rules update required.")
        new_rules = []

        # delete keys first
        for key in delete_keys:
            del rules[key]
        
        if len(rules) > 1 and "NO_ELK_DESTINATIONS" in rules:
            del rules["NO_ELK_DESTINATIONS"]

        # if there are no keys then we need to create a bogus rule
        # must always be atleast one rule
        if len(rules) == 0:
            new_rule = {
                "final": True,
                "filter": "elk_destination=='NO_ELK_DESTINATIONS'",
                "output": "devnull"
            }
            new_rules.append(new_rule)

        # recreate rule list of dicts
        for key in rules:
            new_rule = {
                "final": True,
                "filter": "elk_destination=='%s'" % key,
                "output": rules[key]
            }
            new_rules.append(new_rule)

        json_elk_output_router["rules"] = new_rules
        res = cribl_update_destination(cribl_url, cribl_auth_token, elk_output_router_name, json_elk_output_router)

    ###########################################################################
    # DELETE outputs that are not in elk defintions
    ###########################################################################
    for cribl_output in cribl_elk_outputs:
        
        found = False
        for elk_def in elk_definitions:
            if elk_def["label"] == cribl_output["id"]:
                found = True
        if found == True:
            continue

        # First remove rule from OUTPUT elk_outputs_router if exists
        index_found = find_rule_index(json_elk_output_router, cribl_output["id"])
        if index_found != -1:
            del json_elk_output_router["rules"][index_found]
            res = cribl_update_destination(cribl_url, cribl_auth_token, elk_output_router_name, json_elk_output_router)

        # Second delete output
        res = cribl_delete_destination(cribl_url, cribl_auth_token, cribl_output["id"])

    ###########################################################################
    # MODIFY outputs that do not match elk definitions
    ###########################################################################
    for cribl_output in cribl_elk_outputs:

        for elk_def in elk_definitions:
            if elk_def["label"] == cribl_output["id"]:

                update_required = False

                if cribl_output["url"] != elk_def["url"]:
                    cribl_output["url"] = elk_def["url"]
                    update_required = True

                if cribl_output["auth"]["username"] != elk_def["username"]:
                    cribl_output["auth"]["username"] = elk_def["username"]
                    update_required = True

                if cribl_output["auth"]["password"] != elk_def["password"]:
                    cribl_output["auth"]["password"] = elk_def["password"]
                    update_required = True
                
                if update_required == True:
                    res = cribl_update_destination(cribl_url, cribl_auth_token, cribl_output["id"], cribl_output)

if __name__ == "__main__":
    main()