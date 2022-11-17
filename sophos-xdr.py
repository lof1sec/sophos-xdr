#!/usr/bin/python3
'''
:::::API Script to Query Sophos XDR Data Lake:::::
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

###################################
###  Enter the API credentials  ###
client_id = "111-111-111-111"
client_secret = "11111111111"
###################################

###   Don't modify from here!   ###

# Get the "JWT Token"
url_1 = "https://id.sophos.com/api/v2/oauth2/token"
body_1 = "grant_type=client_credentials&client_id=" + str(client_id) + "&client_secret=" + str(client_secret) + "&scope=token"
headers_1 = {"Content-Type": "application/x-www-form-urlencoded"}
response_1 = requests.post(url_1, headers=headers_1, data=body_1)
response_1_txt = str(response_1.text)
data_1 = json.loads(response_1_txt)
jwt_token = data_1["access_token"]

# Get the "Tenant-ID" and "Data-Region"
url_2 = "https://api.central.sophos.com/whoami/v1"
headers_2 = {"Authorization": "Bearer " + jwt_token}
response_2 = requests.get(url_2, headers=headers_2)
response_2_txt = str(response_2.text)
data_2 = json.loads(response_2_txt)
tenant_id = data_2["id"]
data_region = data_2["apiHosts"]["dataRegion"]

# Query Data Lake with XDR-Schema, Get the "Query-ID" and "Status" of search
url_4 = str(data_region) + "/xdr-query/v1/queries/runs"
headers_4 = {"X-Tenant-ID": tenant_id,"Authorization": "Bearer " + jwt_token,"Accept": "application/json","Content-Type": "application/json"}
# SQL Schema "sophos_ips_windows"
body_5 = {"adHocQuery": {"template": "SELECT\npids, sophos_pids, source_ip, destination_ip, destination_port, protocol, timestamps\nFROM\nxdr_data\nWHERE\nquery_name = 'sophos_ips_windows'\nlimit 10"}}
# SQL Schema "sophos_events_windows"
body_4 = {"adHocQuery": {"template": "SELECT\nevent_timestamp, summary_json, severity, app\nFROM\nxdr_data\nWHERE\nquery_name = 'sophos_events_windows'\nlimit 50"}}
response_4 = requests.post(url_4, headers=headers_4, json=body_4)
response_4_txt = str(response_4.text)
data_4 = json.loads(response_4_txt)
id = data_4["id"]
status_id = data_4["status"]

# Retriving the results (last 24 hours), save in a file the logs from the last 10 minutes
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
        new_timestamp = timestamp_from - 600
        with open("sophos-xdr-status.txt", "a") as f:
            f.write("Query the Sophos Data Lake at ")
            f.write(created)
            f.write("\n")
            f.write("New Cycle in 10 minutes...")
            f.write("\n")
        print("Running...")
        print(created)
        time.sleep(5)
    else:
        response_6 = requests.get(url_6, headers=headers_6)
        response_6_txt = str(response_6.text)
        status = False
        data_6 = json.loads(response_6_txt)
        pages = data_6["pages"]["items"]
        y = int(pages) - 1
        x = 0
        for x in range(0, y):   
            summary_json = data_6["items"][x]["summary_json"]
            event_timestamp = data_6["items"][x]["event_timestamp"]
            x = x + 1
            dt_3 = re.search("^([^\.]+)\.*\d*Z$", event_timestamp)
            dt_4 = dt_3.group(1) + "Z"
            timestamp_to = datetime.strptime(dt_4, '%Y-%m-%dT%H:%M:%S%z').replace(tzinfo=timezone.utc).timestamp()
            if (timestamp_to >= new_timestamp):
                with open("sophos-xdr-logs.txt", "a") as f:
                    f.write(summary_json)
                    f.write("\n")
