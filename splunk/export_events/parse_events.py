import os, sys, re
import time
import subprocess
from datetime import datetime, timedelta

def date_range(earliest, latest, interval, time_format="%m/%d/%Y:%H:%M:%S"):
    earliest = datetime.strptime(earliest,time_format)
    latest = datetime.strptime(latest,time_format)
    diff = (latest  - earliest ) / interval
    for i in range(interval):
        yield (earliest + diff * i).strftime(time_format)
    yield latest.strftime(time_format)

def splunk_search(search_string, header=False):
    #print(search_string)
    splunk_cmd = "/opt/splunk/bin/splunk"
    ret = subprocess.run([splunk_cmd, "search", search_string, "-header", str(header), "-maxout", "0"], capture_output=True)
    ret_stdout = ret.stdout
    return ret_stdout.decode("utf-8").strip()

def splunk_search_raw(search_string, header=False):
    #print(search_string)
    splunk_cmd = "/opt/splunk/bin/splunk"
    ret = subprocess.run([splunk_cmd, "search", search_string, "-header", str(header), "-maxout", "0", "-output", "csv"], capture_output=True)
    ret_stdout = ret.stdout
    return ret_stdout.decode("utf-8").strip()

def splunk_indexes():
    search = "| eventcount summarize=false index=* | dedup index | fields index"
    indexes = splunk_search(search).splitlines()
    return indexes

def splunk_index_epoch_range():
    search = "index=*  | stats earliest(_time) AS Earliest, latest(_time) AS Latest by index"
    encoded_indexes = splunk_search(search)
    lines = encoded_indexes.decode("utf-8").splitlines()
    index_ranges = {}
    for line in lines:
        (index, earliest, latest) = line.split()
        index_ranges[index] = {}
        index_ranges[index]["earliest"] = earliest
        index_ranges[index]["latest"] = latest

def splunk_search_epoch_range(search_string):
    search = "%s  | stats earliest(_time) AS Earliest, latest(_time) AS Latest by index" % search_string
    encoded_indexes = splunk_search(search)
    lines = encoded_indexes.decode("utf-8").splitlines()
    index_ranges = {}
    for line in lines:
        (index, earliest, latest) = line.split()
        index_ranges[index] = {}
        index_ranges[index]["earliest"] = earliest
        index_ranges[index]["latest"] = latest
    return index_ranges

def convert_to_epoch(date_string, time_format="%m/%d/%Y:%H:%M:%S"):
    timestruct = time.strptime(date_string, time_format)
    return time.mktime(timestruct)

def get_index_count_by_span(index, earliest_date, latest_date, span):
    
    ss = '| tstats count as EventCount where index=%s' % index
    ss += ' earliest="%s" latest="%s" groupby index,_time span=%s' % (earliest_date, latest_date, span)
    ss += ' | eval EventCount = if(isnull(EventCount),0,EventCount)'
    ss += ' | eval formattime = strftime(_time,"%m/%d/%Y:%H:%M:%S") | fields - _time'
    # print(ss)
    #sys.exit()
    results = splunk_search(ss).splitlines()
    records = []
    for result in results:
        flds = result.split()
        record = {
            "index": index,
            "seconds": flds[2],
            "num_events": int(flds[1]),
            "processed": False
        }
        records.append(record)

    return records

def main():

    index = "_internal"
    num_forks = 5
    earliest_date = "11/01/2022:04:02:21"
    latest_date = "11/16/2022:04:02:29"
    max_event_count = 49999

    indexes = splunk_indexes()

    for index in indexes:

        span_seconds = get_index_count_by_span(index, earliest_date, latest_date, "1s" )
        current_num_events = 0
        current_earliest = earliest_date
        current_latest = latest_date
        batches = []
        record = None

        if len(span_seconds) == 0:
            print("index %s has no events for this time range." % index)
            continue
        for s in range(len(span_seconds)):
            record = span_seconds[s]
            if record["num_events"] > max_event_count:
                print("Must resolve: ", record)
                continue
            
            current_num_events = current_num_events + record["num_events"]
            if current_num_events < max_event_count:
                current_latest = record["seconds"]
                continue
            batch = {
                "index": index,
                "earliest": current_earliest,
                "latest": current_latest,
                "num_events": current_num_events - record["num_events"],
                "status": "initial"
            }
            batches.append(batch)
            current_num_events = record["num_events"]
            current_earliest = record["seconds"]
            current_latest = record["seconds"]

        batch = {
            "index": index,
            "earliest": current_earliest,
            "latest": current_latest,
            "num_events": current_num_events - record["num_events"],
            "status": "initial"
        }
        batches.append(batch)

        count = 0
        for batch in batches:
            print(str(count), batch)
            count = count + 1
            continue
            search = "index=%s earliest=%s latest=%s" % (index, batch["earliest"], batch["latest"])
            print()
            print(search)
            result = splunk_search_raw(search)
            #print(result)


if __name__ == "__main__":
    main()