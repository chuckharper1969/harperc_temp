import os, sys
import json
import requests

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

def hydrant_get_elk_destinations(url, username, password):

    cwd = os.path.dirname(os.path.realpath(__file__))
    file_path = os.path.join(cwd, "config", "elk_definitions.json")
    try:
        f = open(file_path)
    except Exception as e:
        raise("Failed opening new_elk_output json file [%s]" % str(e))
    
    json_obj = json.load(f)

    f.close()

    return(json_obj)

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
        print(r.text)
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
        print(r.json)
        print(r.text)
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

def main():
    ###########################################################################
    # CONFIGURATION
    ###########################################################################
    cwd = os.path.dirname(os.path.realpath(__file__))

    json_file_config = os.path.join(cwd, "config", "config.json")
    json_config = load_json_file(json_file_config)

    cribl_url = json_config["cribl_conn"]["url"]
    cribl_username = json_config["cribl_conn"]["username"]
    cribl_password = json_config["cribl_conn"]["password"]

    hydrant_url = json_config["hydrant_conn"]["url"]
    hydrant_username = json_config["hydrant_conn"]["username"]
    hydrant_password = json_config["hydrant_conn"]["password"]

    json_elk_output_router = None
    elk_output_router_name = json_config["elk_output_router_name"]
    elk_output_prefix = json_config["elk_output_prefix"]

    output_template_path = os.path.join(cwd, "config", json_config["output_template"])
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

    source_rules = {}
    source_outputs = {}
    for definition in elk_definitions:
        source_rule = {}
        source_rule["filter"] = "elk_destination=='%s'" % definition
        source_rule["output"] = elk_output_prefix + definition
        source_rule["description"] = elk_definitions[definition]["description"]
        source_rule["final"] = True
        source_rules[definition] = source_rule

        source_output = load_json_file(output_template_path) # load template
        source_output["id"] = source_rule["output"]
        source_output["url"] = elk_definitions[definition]["url"]
        source_output["auth"]["username"] = elk_definitions[definition]["username"]
        source_output["auth"]["password"] = elk_definitions[definition]["password"]
        source_outputs[definition] = source_output

    target_rules = {}
    target_outputs = {}
    for target_output in cribl_elk_outputs:
        outputs_key = target_output["id"].replace(elk_output_prefix, "")
        target_outputs[outputs_key] = target_output

    for target_rule in json_elk_output_router["rules"]:
        rules_key = target_rule["output"].replace(elk_output_prefix, "")
        target_rules[rules_key] = target_rule
    
    ###########################################################################
    # ADD new outputs from ELK defs that are not already in Cribl
    # OUTPUTS have to be added first before rules can be assigned to router
    ###########################################################################
    for source_output in source_outputs:
        if not source_output in target_outputs:
            cribl_add_destination(cribl_url, cribl_auth_token, source_outputs[source_output])
    
    ###########################################################################
    # Update rules in Output Router if neccessary
    # Rules have to be removed first before Cribl Destinations can be DELETED
    ###########################################################################
    recreate_rules = False
    for source_rule in source_rules:
        #
        # Check if rule needs to be added
        if not source_rule in target_rules:
            new_rule = {}
            new_rule["filter"] = "elk_destination=='%s'" % source_rule
            new_rule["output"] = elk_output_prefix + source_rule
            new_rule["description"] = source_rules[source_rule]["description"]
            new_rule["final"] = True
            target_rules[source_rule] = new_rule
            recreate_rules = True
            continue
        #
        # Check if rule needs to be updated
        if not source_rules[source_rule]["filter"] == target_rules[source_rule]["filter"]:
            target_rules[source_rule]["filter"] = source_rules[source_rule]["filter"]
            recreate_rules = True
        if not source_rules[source_rule]["output"] == target_rules[source_rule]["output"]:
            target_rules[source_rule]["output"] = source_rules[source_rule]["output"]
            recreate_rules = True
        if not source_rules[source_rule]["description"] == target_rules[source_rule]["description"]:
            target_rules[source_rule]["description"] = source_rules[source_rule]["description"]
            recreate_rules = True

    ###########################################################################
    # Delete rules in Output Router if neccessary
    # Rules have to be removed first before Cribl Destinations can be DELETED
    ###########################################################################
    rules_copy = target_rules.copy()
    for target_rule in rules_copy:
        if not target_rule in source_rules:
            del target_rules[target_rule]
            recreate_rules = True
    
    ###########################################################################
    # If neccessary update Output Router in Cribl
    ###########################################################################
    if recreate_rules == True:
        print("Need to recreate rules in router.")
        if len(target_rules) == 0:
            rules_key = "NO_ELK_DESTINATIONS"
            new_rule = {}
            new_rule["filter"] = "elk_destination=='%s'" % rules_key
            new_rule["output"] = "devnull"
            new_rule["description"] = "Must always be atleast 1 rule"
            new_rule["final"] = True
            target_rules[rules_key] = new_rule
        
        new_rules = []
        for rule in target_rules:
            new_rules.append(target_rules[rule])
        json_elk_output_router["rules"] = new_rules

        cribl_update_destination(cribl_url, cribl_auth_token, elk_output_router_name, json_elk_output_router)

    ###########################################################################
    # Remove any cribl outputs that are no longer in source
    ###########################################################################
    for target_output in target_outputs:
        if not target_output in source_outputs:
            print("Removing %s output" % target_outputs[target_output]["id"])
            cribl_delete_destination(cribl_url, cribl_auth_token, target_outputs[target_output]["id"])
    
    ###########################################################################
    # Update any cribl outputs that so not match source
    ###########################################################################
    for target_output in target_outputs:

        if not target_output in source_outputs:
            continue

        update_required = False
        if not target_outputs[target_output]["auth"]["username"] == source_outputs[target_output]["auth"]["username"]:
            target_outputs[target_output]["auth"]["username"] = source_outputs[target_output]["auth"]["username"]
            update_required = True
        if not target_outputs[target_output]["auth"]["password"] == source_outputs[target_output]["auth"]["password"]:
            target_outputs[target_output]["auth"]["password"] = source_outputs[target_output]["auth"]["password"]
            update_required = True
        if not target_outputs[target_output]["url"] == source_outputs[target_output]["url"]:
            target_outputs[target_output]["url"] = source_outputs[target_output]["url"]
            update_required = True
        if update_required == False:
            continue

        cribl_update_destination(cribl_url, cribl_auth_token, target_outputs[target_output]["id"], target_outputs[target_output])
        
if __name__ == "__main__":
    main()