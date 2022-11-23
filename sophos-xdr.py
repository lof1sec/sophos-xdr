#!/usr/bin/python3
'''
:::::Script to Query Sophos XDR DataLake:::::
Author:     J.Chacano
Reference:  https://developer.sophos.com/getting-started-tenant
            https://developer.sophos.com/getting-started-with-xdr-query
            https://docs.sophos.com/central/References/schemas/index.html?schema=xdr_schema_docs
'''

from ast import While
import requests
import re
import time
import datetime
from datetime import datetime, timezone
import json
import urllib.parse

###################################
###  Enter the API credentials  ###
client_id = "11111111-111111-111111-111111-11111111111"
client_secret = "1111111111111111111111111111111111111111111"
###################################

###   Don't modify from here!   ###

# Get the JWT Token
url_1 = "https://id.sophos.com/api/v2/oauth2/token"
body_1 = "grant_type=client_credentials&client_id=" + str(client_id) + "&client_secret=" + str(client_secret) + "&scope=token"
headers_1 = {"Content-Type": "application/x-www-form-urlencoded"}
response_1 = requests.post(url_1, headers=headers_1, data=body_1)
response_1_txt = str(response_1.text)
data_1 = json.loads(response_1_txt)
jwt_token = data_1["access_token"]

# Get the Tenant-ID and Data-Region
url_2 = "https://api.central.sophos.com/whoami/v1"
headers_2 = {"Authorization": "Bearer " + jwt_token}
response_2 = requests.get(url_2, headers=headers_2)
response_2_txt = str(response_2.text)
data_2 = json.loads(response_2_txt)
tenant_id = data_2["id"]
data_region = data_2["apiHosts"]["dataRegion"]

# SQL template "sophos_events_windows"
body_7 = {
  "adHocQuery": {
    "template": "SELECT\nmeta_username, meta_mac_address, meta_public_ip, severity, meta_ip_address, meta_hostname, event_timestamp, meta_endpoint_type, resource_id, summary_json, meta_os_name, meta_os_platform, threat_name, query_name, counter, component_id\nFROM\nxdr_data\nWHERE\nquery_name = 'sophos_events_windows'\nlimit 500"
  }
}

# Query the DataLake with a XDR-Schema template, Get the "Query-ID" and "Status" results
url_4 = str(data_region) + "/xdr-query/v1/queries/runs"
headers_4 = {"X-Tenant-ID": tenant_id,"Authorization": "Bearer " + jwt_token,"Accept": "application/json","Content-Type": "application/json"}
response_4 = requests.post(url_4, headers=headers_4, json=body_7)
response_4_txt = str(response_4.text)
data_4 = json.loads(response_4_txt)
id = data_4["id"]
status_id = data_4["status"]

# Retrive the results for the last 24 hours and save in a file the last 10 minutes logs
url_5 = data_region + "/xdr-query/v1/queries/runs/" + id
headers_5 = {"X-Tenant-ID": tenant_id,"Authorization": "Bearer " + jwt_token,"Content-Type": "application/json"}
url_6 = data_region + "/xdr-query/v1/queries/runs/" + id + "/results"
headers_6 = {"X-Tenant-ID": tenant_id,"Authorization": "Bearer " + jwt_token,"Content-Type": "application/json"}
status = True
while status:
    if (status_id == "pending"):
        response_5 = requests.get(url_5, headers=headers_5)
        response_5_txt = str(response_5.text)
        data_5 = json.loads(response_5_txt)
        status_id = data_5["status"]
        created = data_5["to"]
        dt_1 = re.search("([^\.]+)\.\d+Z", created)
        dt_2 = dt_1.group(1) + "Z"
        timestamp_from = datetime.strptime(dt_2, '%Y-%m-%dT%H:%M:%S%z').replace(tzinfo=timezone.utc).timestamp()
        new_timestamp = timestamp_from - 1800
        print("Running...")
        time.sleep(15)
    else:
        response_6 = requests.get(url_6, headers=headers_6)
        response_6_txt = str(response_6.text)
        status = False
        data_6 = json.loads(response_6_txt)
        pages = data_6["pages"]["size"]
        y = int(pages)
        x = 0
        with open("sophos-xdr-logs.txt", "w") as f:
            f.write("\n")

        for x in range(0, y):
            summary_json = data_6["items"][x]["summary_json"]
            event_timestamp = data_6["items"][x]["event_timestamp"]
            log_xdr = data_6["items"][x]
            logxdr = str(log_xdr)
            x = x + 1
            dt_3 = re.search("^([^\.]+)\.*\d*Z$", event_timestamp)
            dt_4 = dt_3.group(1) + "Z"
            timestamp_to = datetime.strptime(dt_4, '%Y-%m-%dT%H:%M:%S%z').replace(tzinfo=timezone.utc).timestamp()
            if (timestamp_to >= new_timestamp):
                with open("sophos-xdr-logs.txt", "a") as f:
                    f.write(logxdr)
                    f.write(str())
response_6 = requests.get(url_6, headers=headers_6)
response_6_txt = str(response_6.text)
data_6 = json.loads(response_6_txt)
pages = data_6["pages"]["size"]
from_key = data_6["pages"]["nextKey"]
total = data_6["pages"]["total"]
encoded_from_key = urllib.parse.quote(from_key)
items = data_6["pages"]["items"]
from_key1 = str(encoded_from_key)
z = total - 1
for x in range(1, z):
    url_7 = data_region + "/xdr-query/v1/queries/runs/" + id + "/results?pageFromKey=" + from_key1
    headers_7 = {"X-Tenant-ID": tenant_id,"Authorization": "Bearer " + jwt_token,"Content-Type": "application/json"}
    response_7 = requests.get(url_7, headers=headers_6)
    response_7_txt = str(response_7.text)
    data_7 = json.loads(response_7_txt)
    items_z = data_7["items"]
    len_1 = len(items_z)
    pages = data_7["pages"]["size"]
    total = data_7["pages"]["total"]
    items = data_7["pages"]["items"]
    yy = int(len_1)
    for xp in range(0, yy):
        summary_json = data_7["items"][xp]["summary_json"]
        event_timestamp = data_7["items"][xp]["event_timestamp"]
        log_xdr = data_7["items"][xp]
        logxdr = str(log_xdr)
        xp = xp + 1
        dt_3 = re.search("^([^\.]+)\.*\d*Z$", event_timestamp)
        dt_4 = dt_3.group(1) + "Z"
        timestamp_to = datetime.strptime(dt_4, '%Y-%m-%dT%H:%M:%S%z').replace(tzinfo=timezone.utc).timestamp()
        if (timestamp_to >= new_timestamp):
            with open("sophos-xdr-logs.txt", "a") as f:
                f.write(logxdr)
                f.write("\n")
    from_key = data_7["pages"]["nextKey"]
    encoded_from_key = urllib.parse.quote(from_key)
    from_key1 = str(encoded_from_key)
url_7 = data_region + "/xdr-query/v1/queries/runs/" + id + "/results?pageFromKey=" + from_key1
headers_7 = {"X-Tenant-ID": tenant_id,"Authorization": "Bearer " + jwt_token,"Content-Type": "application/json"}
response_7 = requests.get(url_7, headers=headers_6)
response_7_txt = str(response_7.text)
data_7 = json.loads(response_7_txt)
items_z = data_7["items"]
len_1 = len(items_z)
pages = data_7["pages"]["size"]
total = data_7["pages"]["total"]
items = data_7["pages"]["items"]
yy = int(len_1)
for xp in range(0, yy):
    summary_json = data_7["items"][xp]["summary_json"]
    event_timestamp = data_7["items"][xp]["event_timestamp"]
    log_xdr = data_7["items"][xp]
    logxdr = str(log_xdr)
    xp = xp + 1
    dt_3 = re.search("^([^\.]+)\.*\d*Z$", event_timestamp)
    dt_4 = dt_3.group(1) + "Z"
    timestamp_to = datetime.strptime(dt_4, '%Y-%m-%dT%H:%M:%S%z').replace(tzinfo=timezone.utc).timestamp()
    if (timestamp_to >= new_timestamp):
        with open("sophos-xdr-logs.txt", "a") as f:
            f.write(logxdr)
            f.write("\n")
print("End of task...")
