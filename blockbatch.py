from datetime import datetime, timedelta
from collections import Counter
import os
import re
import json
import csv
import sys
import requests
import argparse
import logging

# Defining the arguments.
argparser=argparse.ArgumentParser()
argparser.add_argument('-c','--config', required=False, type=str, help="Optionally provide a path to a JSON file containing configuration options. If not provided, options must be supplied using command line flags.")
argparser.add_argument('--server', required=False, help="Required: The name of your server (e.g. `darkfriend.social`).")
argparser.add_argument('--access-token', required=False, help="Required: The access token can be generated at https://<server>/settings/applications.")
argparser.add_argument('--type', required=True, type=str, choices=['domain','email','ip'], help="Type of block to be acted on. Options include domain, email, and ip.")
argparser.add_argument('--action', required=True, type=str, default="lookup", choices=['lookup','add','update','remove'], help="The action to be taken. Options include lookup, add, update, remove.")
argparser.add_argument('--file', required=True, type=open, help="The comma-delimited csv file you want to use as a list.")
argparser.add_argument('--mode', required=True, type=str, choices=['report','update'], default="report", help="Specify whether you want to run this in update mode or not. If run in report mode, no actions will be taken. If run in update mode, actions will be taken.")
argparser.add_argument('--log-level', required=False, type=str, choices=['info','debug','error'], default="info", help="Specify the log level. Options include info, debug, and error.")
argparser.add_argument('--log-directory', required=False, type=str, default="logs", help="Specify the log directory.")

# Date and time stamps to be used
dateStamp = datetime.now().strftime("%Y-%m-%d")
timeStamp = datetime.now().strftime("%Y-%m-%d %H_%M_%S")

# Types
def type_domain(server, access_token, action, mode, data):
    # Get domain limits from server
    domain_limits = get_domain_limits(server, access_token)
    sample = data[0]
    if (('domain' not in sample.keys())):
        pl("error", f"Your file does not contain the required header: domain")
        sys.exit(1)
    
    # Action switch
    match action:
        case "lookup":
            lookup_found = find_similar_dicts(data, domain_limits, "domain", "input")
            lookup_not_found = find_dissimilar_dicts(data, domain_limits, "domain", "input")
            if len(lookup_found) > 0:
                write_report(f"reports\domain_{action}_existing_{mode}_{timeStamp}.csv",lookup_found)
            if len(lookup_not_found) > 0:
                write_report(f"reports\domain_{action}_new_{mode}_{timeStamp}.csv",lookup_not_found)
        
        case "add":
            # Get the records from the source that are already blocked
            lookup_found = find_similar_dicts(data, domain_limits, "domain", "source")
            # Get the records from the input that are not in existing domain limits
            lookup_not_found = find_dissimilar_dicts(data, domain_limits, "domain", "input")
            # Process request
            action_add_resp = action_add(server,access_token,lookup_found,lookup_not_found,"domain",mode)

            # Write the report files
            if (len(action_add_resp["successes"]) > 0):
                write_report(f"reports\domain_{action}_blockedDomains_{mode}_{timeStamp}.csv",action_add_resp["successes"])
            if (len(action_add_resp["failures"]) > 0):
                write_report(f"reports\domain_{action}_failedDomainBlocks_{mode}_{timeStamp}.csv",action_add_resp["failures"])
        
        case "update":
            # Get the records from the input that matched existing domain limits
            lookup_found_input = find_similar_dicts(data, domain_limits, "domain", "input")
            # Get the records from the source that matched from the input file
            lookup_found_source = find_similar_dicts(data, domain_limits, "domain", "source")
            # Get the records from the input that are not in existing domain limits
            lookup_not_found = find_dissimilar_dicts(data, domain_limits, "domain", "input")
            # Process request
            action_update_resp = action_update(server,access_token,lookup_found_source,lookup_found_input,lookup_not_found,"domain",mode)
         
            # Write the report files
            if (len(action_update_resp["successes"]) > 0):
                write_report(f"reports\domain_{action}_updatedDomains_{mode}_{timeStamp}.csv",action_update_resp["successes"])
            if (len(action_update_resp["failures"]) > 0):
                write_report(f"reports\domain_{action}_failedDomainUpdates_{mode}_{timeStamp}.csv",action_update_resp["failures"])
        
        case "remove":
            # Get the records from the source that matched from the input file
            lookup_found = find_similar_dicts(data, domain_limits, "domain", "source")
            # Get the records from the input that are not in existing domain limits
            lookup_not_found = find_dissimilar_dicts(data, domain_limits, "domain", "input")
            # Process removals
            action_remove_resp = action_remove(server,access_token,lookup_found,lookup_not_found,"domain",mode)

            # Write the report files
            if (len(action_remove_resp["successes"]) > 0):
                write_report(f"reports\domain_{action}_removedDomains_{mode}_{timeStamp}.csv",action_remove_resp["successes"])
            if (len(action_remove_resp["failures"]) > 0):
                write_report(f"reports\domain_{action}_failedDomainRemovals_{mode}_{timeStamp}.csv",action_remove_resp["failures"])

def type_email(server, access_token, action, mode, data):
    # Get email domain blocks from server
    email_domain_blocks = get_email_domain_blocks(server, access_token)
    sample = data[0]
    if (('domain' not in sample.keys())):
        pl("error", f"Your file does not contain the required header: domain")
        sys.exit(1)
    
    # Action switch
    match action:
        case "lookup":
            lookup_found = find_similar_dicts(data,email_domain_blocks,"domain","source")
            lookup_not_found = find_dissimilar_dicts(data,email_domain_blocks,"domain","input")
            if len(lookup_found) > 0:
                write_report(f"reports\email_{action}_existing_{mode}_{timeStamp}.csv",lookup_found)
            if len(lookup_not_found) > 0:
                write_report(f"reports\email_{action}_new_{mode}_{timeStamp}.csv",lookup_not_found)

        case "add":
            # Get the records from the source that are already blocked
            lookup_found = find_similar_dicts(data, email_domain_blocks, "domain", "source")
            # Get the records from the input that are not in existing domain limits
            lookup_not_found = find_dissimilar_dicts(data, email_domain_blocks, "domain", "input")
            # Process the request
            action_add_resp = action_add(server,access_token,lookup_found,lookup_not_found,"email",mode)

            # Write the report files
            if (len(action_add_resp["successes"]) > 0):
                write_report(f"reports\email_{action}_blockedEmailDomains_{mode}_{timeStamp}.csv",action_add_resp["successes"])
            if (len(action_add_resp["failures"]) > 0):
                write_report(f"reports\email_{action}_failedEmailDomainBlocks_{mode}_{timeStamp}.csv",action_add_resp["failures"])

        case "update":
            pl("info", f"Type: email. Action: {action}. Mode: {mode}. Email domain blocks do not have an {action} action.")

        case "remove":
            # Get the records from the source that matched from the input file
            lookup_found = find_similar_dicts(data, email_domain_blocks, "domain", "source")
            # Get the records from the input that are not in existing domain limits
            lookup_not_found = find_dissimilar_dicts(data, email_domain_blocks, "domain", "input")
            # Process removals
            action_remove_resp = action_remove(server,access_token,lookup_found,lookup_not_found,"email",mode)

            # Write the report files
            if (len(action_remove_resp["successes"]) > 0):
                write_report(f"reports\email_{action}_removedEmailDomains_{mode}_{timeStamp}.csv",action_remove_resp["successes"])
            if (len(action_remove_resp["failures"]) > 0):
                write_report(f"reports\email_{action}_failedEmailDomainRemovals_{mode}_{timeStamp}.csv",action_remove_resp["failures"])

def type_ip(server, access_token, action, mode, data):
    # Get IP blocks from server
    ip_blocks = get_ip_blocks(server, access_token)
    sample = data[0]
    if (('ip' not in sample.keys())
        or ('severity' not in sample.keys())
        ):
        pl("error", f"Your file does not contain one of the required headers: ip, severity")
        sys.exit(1)
    # For the inputted records, add on default /32 subnet mask if it's missing
    for entry in data:
        if ("/" not in entry["ip"]):
            entry["ip"] = entry["ip"] + "/32"
    
    # Action switch
    match action:
        case "lookup":
            lookup_found = find_similar_dicts(data, ip_blocks, "ip", "input")
            lookup_not_found = find_dissimilar_dicts(data, ip_blocks, "ip", "input")
            if len(lookup_found) > 0:
                write_report(f"reports\ip_{action}_existing_{mode}_{timeStamp}.csv",lookup_found)
            if len(lookup_not_found) > 0:
                write_report(f"reports\ip_{action}_new_{mode}_{timeStamp}.csv",lookup_not_found)

        case "add":
            # Get the records from the source that are already blocked
            lookup_found = find_similar_dicts(data, ip_blocks, "ip", "source")
            # Get the records from the input that are not in existing ip blocks
            lookup_not_found = find_dissimilar_dicts(data, ip_blocks, "ip", "input")
            # Process request
            action_add_resp = action_add(server,access_token,lookup_found,lookup_not_found,"ip",mode)

            # Write the report files
            if (len(action_add_resp["successes"]) > 0):
                write_report(f"reports\ip_{action}_blockedIps_{mode}_{timeStamp}.csv",action_add_resp["successes"])
            if (len(action_add_resp["failures"]) > 0):
                write_report(f"reports\ip_{action}_failedIpBlocks_{mode}_{timeStamp}.csv",action_add_resp["failures"])

        case "update":
            # Get the records from the input that matched existing ip blocks
            lookup_found_input = find_similar_dicts(data, ip_blocks, "ip", "input")
            # Get the records from the source that matched from the input file
            lookup_found_source = find_similar_dicts(data, ip_blocks, "ip", "source")
            # Get the records from the input that are not in existing ip blocks
            lookup_not_found = find_dissimilar_dicts(data, ip_blocks, "ip", "input")
            # Process updates
            action_update_resp = action_update(server,access_token,lookup_found_source,lookup_found_input,lookup_not_found,"ip",mode)
            
            # Write the report files
            if (len(action_update_resp["successes"]) > 0):
                write_report(f"reports\domain_{action}_updatedDomains_{mode}_{timeStamp}.csv",action_update_resp["successes"])
            if (len(action_update_resp["failures"]) > 0):
                write_report(f"reports\domain_{action}_failedDomainUpdates_{mode}_{timeStamp}.csv",action_update_resp["failures"])

        case "remove":
            # Get the records from the source that matched from the input file
            lookup_found = find_similar_dicts(data, ip_blocks, "ip", "source")
            # Get the records from the input that are not in existing IP blocks
            lookup_not_found = find_dissimilar_dicts(data, ip_blocks, "ip", "input")
            # Process removals
            action_remove_resp = action_remove(server,access_token,lookup_found,lookup_not_found,"ip",mode)

            # Write the report files
            if (len(action_remove_resp["successes"]) > 0):
                write_report(f"reports\ip_{action}_removedIps_{mode}_{timeStamp}.csv",action_remove_resp["successes"])
            if (len(action_remove_resp["failures"]) > 0):
                write_report(f"reports\ip_{action}_failedIpRemovals_{mode}_{timeStamp}.csv",action_remove_resp["failures"])
            
def find_similar_dicts(input, source, key_to_compare, to_return):
    similar_dicts = []
    match to_return:
        case "input":
            # Extract values from input data
            values_to_compare = {d[key_to_compare] for d in source}
            # Filter source based on the extracted value
            similar_dicts = (item for item in input if item[key_to_compare] in values_to_compare)
        case "source":
            # Extract values from input data
            values_to_compare = {d[key_to_compare] for d in input}
            # Filter source based on the extracted value
            similar_dicts = (item for item in source if item[key_to_compare] in values_to_compare)
    
    # Convert to a list and return
    return list(similar_dicts)

def find_dissimilar_dicts(input, source, key_to_compare, to_return):
    dissimilar_dicts = []
    match to_return:
        case "input":
            # Extract values from input data
            values_to_compare = {d[key_to_compare] for d in source}
            # Filter source based on the extracted value
            dissimilar_dicts = (item for item in input if item[key_to_compare] not in values_to_compare)
        case "source":
            # Extract values from input data
            values_to_compare = {d[key_to_compare] for d in input}
            # Filter source based on the extracted value
            dissimilar_dicts = (item for item in source if item[key_to_compare] not in values_to_compare)

    # Convert to a list and return
    return list(dissimilar_dicts)

def find_dict(list_of_dicts, target_value):
    return [d for d in list_of_dicts if target_value in d.values() ]

def get_domain_limits(server, access_token):
    # Get domain limits
    domain_url_limit = 200
    domain_iter = 200
    domain_url_max = 999999
    domain_limits = []
    pl("debug", f"{server}: Getting domain limits")
    # loop through getting all of the domain limits
    while domain_iter == domain_url_limit:
        get_limits_url = f"https://{server}/api/v1/admin/domain_blocks?limit={domain_url_limit}&max_id={domain_url_max}"
        get_limits_resp = requests.get(get_limits_url,headers={"Authorization":f"Bearer {access_token}"},timeout=30)
        if get_limits_resp.status_code == 200:
            resp = get_limits_resp.json()
            domain_iter = len(resp)
            if domain_iter > 0:
                for limit in resp:
                    domain_limits.append(limit)
                domain_url_max = domain_limits[-1]["id"]
        else:
            pl("error", f"{server}: Problem getting domain limits. Status code: {get_limits_resp.status_code}")
            raise Exception(
                f"{server}: Problem getting domain limits. Status code: {get_limits_resp.status_code}"
            )
    pl("debug", f"{server}: {len(domain_limits)} domain limits retrieved.")
    return domain_limits

def get_email_domain_blocks(server, access_token):
    # Get email domain blocks
    url_limit = 200
    url_max = 999999
    domain_iter = 200
    email_domain_blocks = []
    # loop through getting all of the email domain blocks
    while domain_iter == url_limit:
        get_domain_blocks_url = f"https://{server}/api/v1/admin/email_domain_blocks?limit={url_limit}&max_id={url_max}"
        get_domain_blocks_resp = requests.get(get_domain_blocks_url,headers={"Authorization":f"Bearer {access_token}"},timeout=30)
        if get_domain_blocks_resp.status_code == 200:
            resp = get_domain_blocks_resp.json()
            domain_iter = len(resp)
            if domain_iter > 0:
                for block in resp:
                    email_domain_blocks.append(block)
                url_max = email_domain_blocks[-1]["id"]
        else:
            pl("error", f"{server}: Problem getting email domain blocks. Status code: {get_domain_blocks_resp.status_code}")
            raise Exception(
                f"{server}: Problem getting email domain blocks. Status code: {get_domain_blocks_resp.status_code}"
            )
    pl("debug", f"{server}: {len(email_domain_blocks)} email domain blocks retrieved.")
    return email_domain_blocks

def get_ip_blocks(server, access_token):
    # Get ip blocks
    url_limit = 200
    url_max = 999999
    ip_iter = 200
    ip_blocks = []
    # loop through getting all of the ip blocks
    while ip_iter == url_limit:
        get_ip_blocks_url = f"https://{server}/api/v1/admin/ip_blocks?limit={url_limit}&max_id={url_max}"
        get_ip_blocks_resp = requests.get(get_ip_blocks_url,headers={"Authorization":f"Bearer {access_token}"},timeout=30)
        if get_ip_blocks_resp.status_code == 200:
            resp = get_ip_blocks_resp.json()
            ip_iter = len(resp)
            if ip_iter > 0:
                for block in resp:
                    ip_blocks.append(block)
                url_max = ip_blocks[-1]["id"]
        else:
            pl("error", f"{server}: Problem getting IP blocks. Status code: {get_ip_blocks_resp.status_code}")
            raise Exception(
                f"{server}: Problem getting IP blocks. Status code: {get_ip_blocks_resp.status_code}"
            )
    pl("debug", f"{server}: {len(ip_blocks)} ip blocks retrieved.")
    return ip_blocks

def write_report(target,data):
    with open(target, 'w', newline='') as csvfile:
                    pl("info", f"{len(data)} entries selected. Writing {csvfile.name}")
                    fieldnames = data[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(data)

def action_add(server, access_token,found,not_found,type,mode):
    successes = []
    failures = []
    request_url = []

    if (len(found) > 0):
        for entry in found:
            # Add them to failures for writing the report
            failures.append(entry)
    if (len(not_found) == 0):
        pl("info", f"No records from the input file need to be added")
    else:
        for entry in not_found:
            if mode == "update":
                match type:
                    case "domain":
                        request_url = f"https://{server}/api/v1/admin/domain_blocks"
                    case "email":
                        request_url = f"https://{server}/api/v1/admin/email_domain_blocks"
                    case "ip":
                        request_url = f"https://{server}/api/v1/admin/ip_blocks"
                # If set to update, update!
                request_resp = requests.post(request_url, headers={"Authorization": f"Bearer {access_token}"},json=entry)
                details = request_resp.json()
                match request_resp.status_code:
                    case 200:
                        pl("debug", f"{server}: {type} block added. Details: {details}")
                        successes.append(details)
                    case 422:
                        pl("debug", f"{server}: {details}")
                        failures.append(entry)
                    case _:
                        pl("error", f"{server}: {details}")
                        failures.append(entry)
            else:
                # If not set to update, just dump each the entries into successes listing for writing
                successes.append(entry)
    return {"successes": successes, "failures": failures}

def action_update(server, access_token,found_source,found_input,not_found,type,mode):
    successes = []
    failures = []
    request_url = []
    match type:
        case "ip":
            key = "ip"
        case _:
            key = "domain"
    
    # Anything not found gets added to failures
    if (len(not_found) > 0):
        for entry in not_found:
            failures.append(entry)
    # Start working on the updates
    if (len(found_source) > 0):
        for source in found_source:
            update = find_dict(found_input,source[key])
            if (len(update) == 1):
                update = update[0]
                pl("debug", f"Record to be updated: {source}")
                pl("debug", f"Update values: {update}")
                if mode == "update":
                    # If set to update, process the removal
                    ## Determine the request url and relevant key
                    match type:
                        case "domain":
                            request_url = f"https://{server}/api/v1/admin/domain_blocks/{source['id']}"
                        case "email":
                            request_url = f"https://{server}/api/v1/admin/email_domain_blocks/{source['id']}"
                        case "ip":
                            request_url = f"https://{server}/api/v1/admin/ip_blocks/{source['id']}"
                    
                    # Process the request
                    request_resp = requests.put(request_url, headers={"Authorization": f"Bearer {access_token}"}, json=update)
                    details = request_resp.json()
                    match request_resp.status_code:
                        case 200:
                            pl("info", f"{server}: {type} block updated. Details: {details}")
                            successes.append(details)
                        case _:
                            pl("error", f"{server}: {details}")
                            failures.append(update)
                else:
                    # If not set to update, just add to successes for printing the report
                    successes.append(update)
            elif (len(update) > 1):
                pl("error", f"{source[key]}: Search for matches returned more than one")
                pl("error", f"{source[key]}: {update}")
                for u in update:
                    failures.append(u)
            else:
                pl("error", f"{source[key]}: Somehow the search for matches between lists returned zero results this time")
                failures.append(source)
    else:
        pl("error", f"No existing {type} blocks matched the input file")
    return {"successes": successes, "failures": failures}

def action_remove(server,access_token,found,not_found,type,mode):
    successes = []
    failures = []
    request_url = []
    key = []
    
    # Anything not found gets added to failures.
    if (len(not_found) > 0):
        for entry in not_found:
            failures.append(entry)            
    # Start working on the removals
    if (len(found) > 0):
        for source in found:
            if mode == "update":
                # If set to update, process the removal
                ## Determine the request url and relevant key
                match type:
                    case "domain":
                        request_url = f"https://{server}/api/v1/admin/domain_blocks/{source['id']}"
                        key = "domain"
                    case "email":
                        request_url = f"https://{server}/api/v1/admin/email_domain_blocks/{source['id']}"
                        key = "domain"
                    case "ip":
                        request_url = f"https://{server}/api/v1/admin/ip_blocks/{source['id']}"
                        key = "ip"
                
                # Process the request
                request_resp = requests.delete(request_url, headers={"Authorization": f"Bearer {access_token}"})
                match request_resp.status_code:
                    case 200:
                        pl("info", f"{server}: {source[key]} {type} block has been deleted")
                        successes.append(source)
                    case 404:
                        pl("error", f"{server}: {source[key]} {type} block somehow could not be found")
                        failures.append(source)
                    case _:
                        pl("error" f"{server}: {request_resp.status_code}, {request_resp.json()}")
                        failures.append(source)
            else:
                # If not set to update, just add to successes for printing the report
                successes.append(source)
    return {"successes": successes, "failures": failures}

def pl(
        level,
        message
):
    match level:
        case "debug":
            logging.debug(message)
        case "info":
            logging.info(message)
        case "error":
            logging.error(message)
        case _:
            logging.info(message)
    print(message)

if __name__ == "__main__":
    # Getting arguments
    arguments = argparser.parse_args()

    # Pulling from config file
    if(arguments.config != None):
        if os.path.exists(arguments.config):
            with open(arguments.config, "r", encoding="utf-8") as f:
                config = json.load(f)

            for key in config:
                setattr(arguments, key.lower().replace('-','_'), config[key])

        else:
            print(f"Config file {arguments.config} doesn't exist")
            sys.exit(1)
    
    # If no server or access token are specified, quit
    if(arguments.server == None or arguments.access_token == None):
        print("You must supply at least a server name and access token")
        sys.exit(1)
    
    # in case someone provided the server name as url instead,
    setattr(arguments, 'server', re.sub(r"^(https://)?([^/]*)/?$", "\\2", arguments.server))

    #logging
    log_file = arguments.log_directory + "\log_" + dateStamp + ".txt"
    def switch(loglevel):
        if loglevel == "info":
            return logging.INFO
        if loglevel == "debug":
            return logging.DEBUG
        if loglevel == "error":
            return logging.ERROR
        else:
            return logging.INFO
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',filename=log_file, level=switch(arguments.logging_level), datefmt='%Y-%m-%d %H:%M:%S')

    # Pulling in the specified file and turning it into a Dict list
    pl("debug", f"Server: {arguments.server}")
    pl("debug", f"Log level: {arguments.log_level}")
    pl("debug", f"Log directory: {arguments.log_directory}")
    pl("debug", f"File: {arguments.file}")
    data = list(csv.DictReader(arguments.file, delimiter=","))
    pl("info", f"Provided file read. {arguments.file}")
    pl("info", f"{arguments.type}s in file: {len(data)}")
    if(len(data) == 0):
        pl("error", "You must supply a file with one or more record")
        sys.exit(1)

    # Type switch
    match arguments.type:
        case "domain":
            type_domain(arguments.server, arguments.access_token, arguments.action, arguments.mode, data)
        case "email":
            type_email(arguments.server, arguments.access_token, arguments.action, arguments.mode, data)
        case "ip":
            type_ip(arguments.server, arguments.access_token, arguments.action, arguments.mode, data)