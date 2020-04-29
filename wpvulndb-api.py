#!/usr/bin/python
'''
Updates a Slack channel via webhook containing latest vulnerabilities, as they are reported from WPVulnDB's API.

Educational project - professional users should contact https://wpvulndb.com

@author Alex Orfanos
'''

import requests, json, os, sqlite3, logging

f_latest_vuln_counter = '/tmp/wpvulndb_api_latest_vulnerability_id'
f_log_file = "/tmp/wpvulndb-api.log"

# the api has a rate limit
# send a dummy request and fetch response code
def api_status_check(headers):
    _test_api_call = requests.get('https://wpvulndb.com/api/v3/vulnerabilities/10026', headers=headers)
    if _test_api_call.status_code == 403:
        logger.critical("Daily rate limit (250req) reached.")
    else:
        logger.info("Pre-Flight/API-connectivity : {0}".format(_test_api_call, _test_api_call.content))

# get vulnerability information and format in a text block
def get_patch_info(vuln_id, name, title, fixed_in_version, references):
    logger.info("Packing vulnerability information: {0} {1} {2}".format(vuln_id,name,fixed_in_version))
    formatted_info = "<https://wpvulndb.com/vulnerabilities/{0}|{1}>".format(vuln_id,title.replace('<',''))
    logger.debug("Contents: {0}".format(formatted_info))
    return(formatted_info)

def slack_post(slack_data):
    full_data = {}
    full_data["text"] = slack_data
    logger.debug("Sending to Slack: {0}".format(slack_data))
    send_info = requests.post(
            slack_webhook_url, json.dumps(full_data), headers={'Content-Type': 'application/json'})

    if send_info.status_code != 200:
        raise ValueError(
                'Request to Slack returned %s, response is:\n%s' %(send_info.status_code, send_info.text))
        logger.error("POST to Slack failed, returned: {0}".format(send_info.status_code))

def vuln_check_if_new(current_latest_vuln_id):
    # register top ID from last run in a file
    # and compare it to current call's top ID
    # if id_current > id_last then new_vuln.exists
    logger.info("Checking for new vulnerabilities")
    if os.path.exists(f_latest_vuln_counter):
        # register last top ID
        _last_latest_vuln_id = open(f_latest_vuln_counter, "r").read()
        logger.debug("Last registered: {0}".format(_last_latest_vuln_id))
        if int(current_latest_vuln_id) > int(_last_latest_vuln_id):
            # begin iterating through new plugin id's
            logger.info("Counter is out of date (current:{0} > last local:{1}), begin iterating".format(int(current_latest_vuln_id), int(_last_latest_vuln_id)))
            for vuln_id in range(int(_last_latest_vuln_id)+1, int(current_latest_vuln_id)+1):
                # register new vulnerability
                fetch_vuln_new = requests.get("https://wpvulndb.com/api/v3/vulnerabilities/"+str(vuln_id), headers=wpvulndb_curl_headers).json()
                # register title
                try:
                    _vuln_title = fetch_vuln_new["title"]
                except KeyError:
                    # in case of non-200 return code
                    # nullify to discard from results
                    logger.warn("Found entry with title None ({0})".format(vuln_id))
                    _vuln_title = None
                    pass
                # register name
                # register prefix to be used on _vuln_fixed_in
                try: # if plugin
                    for plugin in fetch_vuln_new["plugins"]:
                        _vuln_fixed_in_prefix = "plugins"
                        _vuln_name = plugin
                except KeyError:
                    try: # if theme
                        for theme in fetch_vuln_new["themes"]:
                            _vuln_fixed_in_prefix = "themes"
                            _vuln_name = theme
                    except KeyError: # if wordpress
                        try:
                            for wordpress in fetch_vuln_new["wordpresses"]:
                                _vuln_fixed_in_prefix = "wordpresses"
                                _vuln_name = wordpress
                        except KeyError: # if all fails
                            # this is handled in _vuln_fixed_in
                            pass
                # register fixed-in-version
                try:
                    _vuln_fixed_in = fetch_vuln_new[_vuln_fixed_in_prefix][_vuln_name]["fixed_in"]
                except KeyError:
                    pass
                if _vuln_fixed_in is None:
                    _vuln_fixed_in = "Issue has not been resolved. Check vuln {0}".format(vuln_id)
                # register references
                try: # if url
                    _vuln_references_full = fetch_vuln_new["references"]["url"]
                    for url in _vuln_references_full:
                        _vuln_reference = url
                except KeyError:
                    try: # if cve
                        _vuln_references_full = fetch_vuln_new["references"]["cve"]
                        for cve in _vuln_references_full:
                            _vuln_reference = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-{0}".format(cve)
                    except KeyError: # if all fails
                        _vuln_reference = "https://wpvulndb.com/vulnerabilities/{0}".format(str(vuln_id))
                
                # populate vuln_compare_table
                logger.debug("INSERT: {0} {1} {2} {3} {4}".format(int(vuln_id),str(_vuln_name),str(_vuln_fixed_in),str(_vuln_title),str(_vuln_reference)))
                db_cursor.execute("insert into vuln_compare_table values ('{0}','{1}', '{2}', '{3}', '{4}')".format(int(vuln_id),str(_vuln_name),str(_vuln_fixed_in),str(_vuln_title),str(_vuln_reference)))
            
            # update _last_latest_vuln_id
            logger.info("Updating latest vulnerability counter")
            _new_last_latest_vuln_id = open(f_latest_vuln_counter, "w").write("{0}".format(int(get_current_latest_vuln_id())))
            _new_value = open(f_latest_vuln_counter, "r").read()
            logger.debug("Updated latest vulnerability counter, new value {0}".format(_new_value))
        else:
            logger.info("No new vulnerabilities to report")
    else: # create the file and append a value, if it doesn't exist
        logger.info("File {0} did not exist, creating it with content {1}".format(f_latest_vuln_counter, str(get_current_latest_vuln_id())))
        open(f_latest_vuln_counter, "w+").write(str(get_current_latest_vuln_id()))
        logger.debug("Created {0}".format(f_latest_vuln_counter))
        # recurse
        logger.info("Running check again...")
        vuln_check_if_new(get_current_latest_vuln_id())

def get_current_latest_vuln_id():
    _current_latest_vuln_id = requests.get('https://wpvulndb.com/api/v3/all/latest', headers=wpvulndb_curl_headers).json()
    for _vuln_info in _current_latest_vuln_id:
        current_latest_vuln_id = _vuln_info["id"]
        break; # break to loop only once, therefore keeping only the first ID
    logger.info("Fetching latest vulnerability ID ({0})".format(current_latest_vuln_id))
    return int(current_latest_vuln_id)

# main
if __name__ == "__main__":
    # initiate logging
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG) #change logging verbosity

    # initiate log handler
    log_handler = logging.FileHandler(f_log_file)
    log_handler.setLevel(logging.DEBUG)

    # create log formatter
    log_formatter = logging.Formatter('[%(levelname)s]\t%(asctime)s\t%(name)s\t%(message)s' )
    log_handler.setFormatter(log_formatter)

    logger.addHandler(log_handler)

    logger.info("---Session start---")

    try:
        wpvulndb_api_token = os.environ['WPVULNDB_API_TOKEN']
        wpvulndb_curl_headers = {'Authorization': 'Token token={}'.format(wpvulndb_api_token)}
        slack_webhook_url = os.environ['SLACK_WEBHOOK_URL']
    except KeyError as err:
        logger.critical("Error: {}".format(err))
        
    api_status_check = api_status_check(wpvulndb_curl_headers)

    # initiate db and create table
    logger.debug('Instantiating in-memory DB')
    db_connect = sqlite3.connect(":memory:")
    logger.debug('DB instantiated successfully.')
    db_cursor = db_connect.cursor()
    logger.debug('Creating vuln_compare_table')
    db_cursor.execute('''create table vuln_compare_table (id int, name text, version text, title text, reference text)''') 
    logger.debug('Created vuln_compare_table')

    vuln_check_if_new(get_current_latest_vuln_id())

    # group vuln_compare_table by name, that way we keep the latest reference to each name
    # , hence the last version mentioned in the API responses. This solves the n-version issue
    for _id, _name, _version, _title, _reference in db_cursor.execute('''select * from vuln_compare_table where title not like '%None%' group by name'''):
        slack_data = "{0}".format(get_patch_info(_id, _name, _title, _version, _reference))
        slack_post(slack_data)

    # commit and close db connection
    logger.debug("Commiting to DB")
    db_connect.commit()
    logger.debug("Closing connection")
    db_connect.close()
    logger.info("---Session end---")
