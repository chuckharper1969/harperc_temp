import time
import socket
import requests
import random
import sys

##############################################################################
# Send HEC event to Splunk
##############################################################################
def send_hec_event(hec_api_url, hec_token, json_event):

    headers = {
        'Accept': 'application/json', 
        'Authorization': 'Splunk %s' % hec_token
    }

    endpoint = "services/collector/event"
    splunk_uri = "%s/%s" % (hec_api_url, endpoint)

    try:
        r = requests.post(splunk_uri, headers=headers, json=json_event, verify=False)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        sys.exit("ERROR: %s" % str(e))

    return r.json()

def main():

    hec_api_url = "http://cribl.maejer.lab:8088"
    hec_token = "d06c9de0-f01e-4f19-954c-69f2d261d19d"
    current_host = socket.gethostname()
    count = 0
    random_int = random.randint(0,1000)
    number_events = 10

    for count in range(number_events):

        instance = "%s-%s" % (random_int, count)
    
        json_event = {
            "time": time.time(),
            "host": current_host,
            "index": "http_stuff",
            "source": "hec",
            "sourcetype": "mj:ABC001:logmessage",
            "uuid": "abcdef-defghi-jklmn-0123456789",
            "wf_env": "non-prod",
            "wf_id": "ABC001",
            "event": {
                "instance":  instance,
                "event_id": "abcdef-defghi-jklmn-0123456789",
                "event_app_name": "CA012345-ABC",
                "event_org_id": "abcdef-defghi-jklmn-0123456789",
                "event_org_name": "CA012345-ABC",
            }
        }

        r_json = send_hec_event(hec_api_url, hec_token, json_event)

        print(str(count), r_json)

if __name__ == "__main__":
    main()
