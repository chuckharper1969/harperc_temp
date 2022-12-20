import concurrent.futures
import requests
import threading
import time
import json
import sys

requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)

thread_local = threading.local()

##############################################################################
# splunk_add_destination
##############################################################################
def splunk_get_search(splunk_url, splunk_username, splunk_password, search_string, output_mode="json"):

    data = {
        "output_mode": output_mode,
        "count": 0,
        "search": "search %s" % search_string
    }

    endpoint = "servicesNS/admin/search/search/jobs/export"
    splunk_uri = "%s/%s" % (splunk_url, endpoint)

    try:
        r = requests.post(splunk_uri, data=data, verify=False, auth=(splunk_username, splunk_password))
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        sys.exit("ERROR: %s" % str(e))

    return r.content.splitlines()

def get_conf():
    if not hasattr(thread_local, "splunk"):
        with open("./config.json") as f:
            thread_local.splunk = json.load(f)
    return thread_local.splunk


def execute_batch(batch):
    splunk_conf = get_conf()
    splunk_username = splunk_conf["username"]
    splunk_password = splunk_conf["password"]
    splunk_url = splunk_conf["url"]
    earliest = batch["earliest"]
    latest = batch["latest"]
    index = batch["index"]
    splunk_search_string = "index=%s earliest=%s latest=%s" % (index, earliest, latest)
    records = splunk_get_search(splunk_url, splunk_username, splunk_password, splunk_search_string)


def execute_batches(batches_json, max_workers=5):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(execute_batch, batches_json)


if __name__ == "__main__":

    max_workers = 5

    with open("./data.json") as f:
        batches_json = json.load(f)["batches"]

    start_time = time.time()

    execute_batches(batches_json, max_workers)

    duration = time.time() - start_time

    print(f"Downloaded {len(batches_json)} in {duration} seconds")