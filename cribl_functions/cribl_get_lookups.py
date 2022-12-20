#!/usr/bin/python

import os, sys
import json
import requests

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

def load_json_file(file_path):

    try:
        f = open(file_path)
    except Exception as e:
        raise("Failed opening new_elk_output json file [%s]" % str(e))
    
    json_obj = json.load(f)

    f.close()

    return(json_obj)

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
def cribl_get_lookups(cribl_url, cribl_token):

    header = {
        'Accept': 'application/json', 
        'Authorization': 'Bearer ' + cribl_token 
    }

    endpoint = "api/v1/system/lookups"
    cribl_uri = "%s/%s" % (cribl_url, endpoint)

    try:
        r = requests.get(cribl_uri, headers=header, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(r.text)
        sys.exit("ERROR: %s" % str(e))
    
    return r.json()

def main():
    cwd = os.path.dirname(os.path.realpath(__file__))

    json_file_config = os.path.join(cwd, "config", "config.json")
    json_config = load_json_file(json_file_config)

    cribl_url = json_config["cribl_conn"]["url"]
    cribl_username = json_config["cribl_conn"]["username"]
    cribl_password = json_config["cribl_conn"]["password"]

    ###########################################################################
    # Get Cribl Token
    ###########################################################################
    cribl_auth_token = auth(cribl_url, cribl_username, cribl_password)

    ###########################################################################
    # Get List of lookups from Cribl
    # GET /api/v1/system/lookups
    ###########################################################################
    cribl_output_items = cribl_get_lookups(cribl_url, cribl_auth_token)
    print(cribl_output_items["items"])

if __name__ == "__main__":
    main()