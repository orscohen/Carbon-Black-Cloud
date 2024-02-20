import requests
import os
import json
import csv
from datetime import datetime, timedelta, timezone
import logging
logging.basicConfig(level=logging.INFO)
#************************************************	
#| Script Configuration:                        |
#| -------------------------------------------  |
#|                                              |
#   ___          ___      _                     |
#  /___\_ __    / __\___ | |__   ___ _ __       |
# //  // '__|  / /  / _ \| '_ \ / _ \ '_ \      |
#/ \_//| |    / /__| (_) | | | |  __/ | | |     |
#\___/ |_|    \____/\___/|_| |_|\___|_| |_|     |
#***********************************************

# Replace with your Carbon Black API credentials
cb_url = "https://defense-eu.conferdeploy.net"
cb_org_key = "XXXXX"
api_key = "YYYYYYY"
api_secret = "DDDDDDDDDD"
combined_key = f"{api_secret}/{api_key}"
# API key permissions required:
#Please create a "Custom" Access Level including each category:
#Background Tasks > Status > jobs.status, allow permission to READ
#Search > Events > org.search.events, allow permission to CREATE
#Device > General Information > device, allow permission to READ
#Policies > org.policies > Allow  org.policies.READ

# Define the time window variable
time_window = "-30d"
#M: month(s)
#w: week(s)
#d: day(s)
#h: hour(s)
#m: minute(s)
#s: second(s)

#headers
headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': combined_key
        }
# Get policies summary
policies_url = f"{cb_url}/policyservice/v1/orgs/{cb_org_key}/policies/summary"
response = requests.get(policies_url, headers=headers)

# Check if the request for policies summary was successful
if response.ok:
    policies = response.json()["policies"]
    print("Available Policies:")
    for idx, policy in enumerate(policies, start=1):
        print(f"{idx}. {policy['name']}")

    # Get the user's choice
    selected_policy_index = int(input("Enter the number corresponding to the desired policy: "))
    selected_policy = policies[selected_policy_index - 1]

  # Get detailed policy information
    policy_details_url = f"{cb_url}/policyservice/v1/orgs/{cb_org_key}/policies/{selected_policy['id']}"
    response = requests.get(policy_details_url, headers=headers)

    # Check if the request for policy details was successful
    if response.ok:
        policy_details = response.json()

def create_query(rule):
    value = rule["application"]["value"].replace("**", "*")
    operation = rule.get("operation")

    query_patterns = {
        "INVOKE_CMD_INTERPRETER": f"(process_name:{value}) AND (childproc_name:cmd.exe OR childproc_name:powershell.exe OR childproc_name:cscript.exe OR childproc_name:wscript.exe OR childproc_name:wmic.exe OR childproc_name:mshta.exe OR childproc_name:sh OR childproc_name:zsh OR childproc_name:csh OR childproc_name:bash OR childproc_name:tcsh OR childproc_name:python)",
        "RUN": f"(process_name:{value})",
        "MEMORY_SCRAPE": f"(process_name:{value}) AND (ttp:RAM_SCRAPING OR ttp:READ_SECURITY_DATA)",
        "CODE_INJECTION": f"(process_name:{value}) AND (ttp:INJECT_CODE OR ttp:HAS_INJECTED_CODE OR ttp:COMPROMISED_PROCESS OR ttp:PROCESS_IMAGE_REPLACED OR ttp:MODIFY_PROCESS OR ttp:MODIFY_PROCESS_EXECUTION OR ttp:HOLLOW_PROCESS))",
        "NETWORK": f"(process_name:{value}) AND (netconn_count:[1 TO *] OR ttp:NETWORK_ACCESS OR ttp:ATTEMPTED_SERVER OR ttp:ATTEMPTED_CLIENT)",
        "POL_INVOKE_NOT_TRUSTED": f"(process_name:{value}) AND (childproc_effective_reputation:NOT_LISTED OR childproc_effective_reputation:UNKNOWN OR childproc_effective_reputation:ADAPTIVE_WHITE_LIST)",
        "RUN_INMEMORY_CODE": f"(process_name:{value}) AND (ttp:SUSPICIOUS_BEHAVIOR OR ttp:PACKED_CALL)",
        "RANSOM": f"(process_name:{value}) AND (ttp:KNOWN_RANSOMWARE OR ttp:DATA_TO_ENCRYPTION OR ttp:SET_SYSTEM_FILE OR ttp:KERNEL_ACCESS)",
        "INVOKE_SCRIPT": f"(process_name:{value}) AND (ttp:FILELESS)"
    }

    reputation_type = rule.get("application", {}).get("type")
    reputation_value = rule.get("application", {}).get("value")

    if reputation_type == "REPUTATION":
        if reputation_value in ["SUSPECT_MALWARE", "KNOWN_MALWARE", "COMPANY_BLACK_LIST", "RESOLVING", "PUP", "ADAPTIVE_WHITE_LIST"]:
            query = query_patterns.get(operation)
            if query:
                query = query.replace(f"(process_name:{value})", f"(process_effective_reputation:{reputation_value})")
        else:
            query = None
    else:
        query = query_patterns.get(operation)

    return query

# Initialize CSV data outside the loop
csv_data = [['Backend Timestamp', 'Device Name', 'Event Type', 'Process Name', 'Value', 'Operation',
             'device_policy_id', 'device_id', 'query', 'process_hash', 'Process GUID link']]

# Check if CSV file already exists
csv_file_name = "query_results_all_rules.csv"
file_exists = os.path.exists(csv_file_name)


# Iterate over rules in the policy
for rule in policy_details.get('rules', []):
    # Check if the rule has the 'operation' key
    if 'operation' in rule:
        # Get the query for the rule
        query = create_query(rule)
        
        # Print the query before making the API call
        print(f"Query for Rule ID {rule['id']} (Operation: {rule['operation']}):")
        print(query)

        # 1.a Create a search job query
        search_job_url = f"{cb_url}/api/investigate/v2/orgs/{cb_org_key}/enriched_events/search_jobs"
        search_job_payload = {
            "criteria": {},
            "query": query,
            "fields": ["*", "process_start_time"],
            "sort": [{"field": "device_timestamp", "order": "asc"}],
            "start": 0,
            "time_range": {"window": time_window}
        }
        search_job_headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': combined_key
        }

        # Make the API call for creating a search job
        search_job_response = requests.post(search_job_url, headers=search_job_headers, json=search_job_payload)
        print(search_job_response.text)

        # Check if the search job creation was successful
        if search_job_response.ok:
            # Extract the job_id from the response
            job_id = search_job_response.json().get('job_id')

            # 1.B Now, take the job id and make the following query
            detail_job_url = f"{cb_url}/api/investigate/v2/orgs/{cb_org_key}/processes/detail_jobs/{job_id}/results"
            detail_job_headers = {
                'Content-Type': 'application/json',
                'accept': 'application/json',
                'X-Auth-Token': combined_key
            }

            # Make the API call for getting detailed job results
            detail_job_response = requests.get(detail_job_url, headers=detail_job_headers)
            print(detail_job_response.text)

            # Check if the detailed job results retrieval was successful
            if detail_job_response.ok:
                # Process the detailed job results
                results = detail_job_response.json().get('results', [])

                # Iterate over each result and extract relevant information
                for result in results:
                    # Extract values from the result
                    backend_timestamp = result.get('backend_timestamp', '')
                    device_name = result.get('device_name', '')
                    event_type = result.get('event_type', '')
                    process_name = result.get('process_name', '')
                    value = result.get('value', '')
                    operation = rule.get('operation', '')
                    device_policy_id = result.get('device_policy_id', '')
                    device_id = result.get('device_id', '')
                    hash_value = result.get('process_hash', '')
                    process_guid = result.get('process_guid', '')
                    process_guid_link = f"{cb_url}/cb/investigate/observations?query={process_guid}"


                    # Check if the exact row is already inside the CSV
                    if [backend_timestamp, device_name, event_type, process_name, value, operation,
                        device_policy_id, device_id, query, hash_value, process_guid_link] not in csv_data:
                        # Append values to the CSV data
                        csv_data.append([backend_timestamp, device_name, event_type, process_name, value,
                                         operation, device_policy_id, device_id, query, hash_value,
                                         process_guid_link])

    # Write data to the CSV file
                    with open(csv_file_name, 'a', newline='') as csv_file:
                        csv_writer = csv.writer(csv_file)
                        # Write data
                        csv_writer.writerows(csv_data)

                    print(f"CSV exported to: {csv_file_name}")

                else:
                    print(f"Error fetching detailed job results: {detail_job_response.text}")

            else:
                print(f"Error fetching policy details: {response.text}")

        else:
            print("Invalid policy selection.")

    else:
        print(f"Error fetching policies: {response.text}")
