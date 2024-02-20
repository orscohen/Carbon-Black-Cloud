from cbc_sdk.rest_api import CBCloudAPI
from cbc_sdk.platform import Policy, Observation
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
api  = CBCloudAPI(profile="default")

# Define the time window variable
time_window = "-30d"
try:
    # Retrieve policies
    policies = list(api.select(Policy))
    if not policies:
        print("No policies found.")
        exit()

    # Display policies and prompt user for selection
    print("Available Policies:")
    for idx, policy in enumerate(policies, start=1):
        print(f"{idx}. {policy.name}")

    selected_policy_index = int(input("Enter the number corresponding to the desired policy: "))
    if selected_policy_index < 1 or selected_policy_index > len(policies):
        print("Invalid policy selection.")
        exit()

    selected_policy = policies[selected_policy_index - 1]
    rules = selected_policy.get('rules')

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
    for rule in rules:
        if 'operation' in rule:
            # Get the query for the rule
            query = create_query(rule)
            if query is None:
                continue  # Skip rules with invalid queries

            # Print the query before making the API call
            print(f"Query for Rule ID {rule['id']} (Operation: {rule['operation']}):")
            print(query)

            # Create an Observation query
            observations = api.select(Observation).where(query).set_time_range(window=time_window)
            for observation in observations:
                # Extract values from the observation
                backend_timestamp = observation.backend_timestamp
                device_name = observation.device_name
                event_type = observation.event_type
                process_name = observation.process_name
                value = observation.get('value', '')
                operation = rule.get('operation', '')
                device_policy_id = observation.device_policy_id
                device_id = observation.device_id
                hash_value = observation.process_hash
                process_guid = observation.process_guid
                process_guid_link = f"{api.url}/cb/investigate/observations?query={process_guid}"

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
                        csv_writer.writerow([backend_timestamp, device_name, event_type, process_name, value,
                                             operation, device_policy_id, device_id, query, hash_value,
                                             process_guid_link])

    print(f"CSV exported to: {csv_file_name}")

except Exception as e:
    print("An error occurred:", str(e))
    # You can also log the exception details using the logging module
    logging.exception("An error occurred")
