#!/usr/bin/env python
# Migrate users from one Docker UCP to another
# Kyle Squizzato <kyle.squizzato@docker.com>

import argparse
import sys
import os
import re
import requests
import logging
import json
from simplediff import diff


""" Yes or no prompting """
def yes_no(question):
    yes = set(['yes','y'])
    no = set(['no','n'])
    prompt = " [Yes / No] "
    while True:
        print question + '?' + prompt
        choice = raw_input().lower()
        if choice == '':
            # If no choice is given, return no
            return False
        if choice in no:
            return False
        if choice in yes:
            return True
        else:
           print "\nPlease respond with 'yes' or 'no'"

"""
Perform retrying for error handling.
Specify componentName which is breaking.
retrySecs is the number of seconds each retry will increment by.
doSomething handles a function to call at the > 3 retry mark.
maxAttempts is an int representing the max number of tries before exiting
(defaults to 1).
"""
def retry_this(componentName, retrySecs, retries, maxAttempts=1,
               doSomething=None):
    retry_time = int(retries)*retrySecs
    if retries > 3:
        # if doSomething isn't given then assume we don't need to run anything
        # at retries > 3
        if not doSomething == None:
            doSomething
    if retries > maxAttempts:
        # Notify user we failed
        logging.error('Unable to access {0} after {1} connection attempts, exiting'.format(componentName, maxAttempts))
        sys.exit(1)
    else:
        logging.info('Unable to access {0}, attempting to reconnect to {0} in {1} seconds'.format(componentName, retry_time))
        sleep(retry_time)
        logging.info("Attempting to reconnect to {0} -- retry {1} of {2}".format(componentName, retries, maxAttempts))

"""
Get and return an authtoken from a given UCP URL
"""
def get_token(username, password, url, retries=0):
    data='{{"username":"{0}","password":"{1}"}}'.format(username, password)
    logging.info('Authenticating with UCP {}...'.format(url))
    try:
        r = requests.post(
            url+'/auth/login',
            data=data,
            verify=False)
    except requests.exceptions.RequestException as e:
        logging.error('Failed to authenticate with UCP {0}: {1}'.format(url, e))
        retries+=1
        retry_this('UCP', 10, retries, 3, get_token(username, password, url))
    a = json.loads(r.text)
    token = str(a["auth_token"])
    return token

"""
Get a JSON dump of users or orgs from a given UCP URL, facilitated by the
/accounts endpoint.  Specify users=True for users, False for orgs.
Use customFilter for custom filters, if desired.

Then, ask the user to verify if the pulled information looks sane.
"""
def get_accounts(authtoken, url, users=True, customFilter=None,
                verifyUser=True):
    headers = {"Authorization":"Bearer {0}".format(authtoken)}
    # Setup filters
    if customFilter != None:
        filters = customFilter
    if users:
        filters = 'users'
    else:
        filters = 'orgs'
    logging.info('Generating a list of {0} from {1}...'.format(filters, url))
    # Make the request
    try:
        r = requests.get(
            '{0}/accounts/?filter={1}'.format(url, filters),
            headers=headers,
            verify=False
        )
    except requests.exceptions.RequestException as e:
        logging.error('Failed to get account list for UCP {0}: {1}'.format(url, e))
        retries+=1
        retry_this('UCP', 10, retries, 3, get_accounts(authtoken, url
                                                       users, customFilter,
                                                       verifyUser))
    logging.info('Getting ready to import the following accounts:\n{}'.format(r.text))
    # Using the captured information send a list of captured accounts out to
    # the user
    a = json.loads(r.text)
    if verifyUser:
        choice = yes_no('Does this appear correct')
        if choice:
            # proceed
            logging.info('Accepted given accounts list, continuing...')
            return a
        if not choice:
            # exit
            logging.error('Accounts list does not appear correct, exiting.')
            sys.exit(1)
    else:
        logging.info('verifyUser flag False, skipping account list verification...')

"""
Import a given JSON dump of accounts into a given UCP URL.
"""
def import_accounts(authtoken, url, accountsJson):
    headers = {"Authorization":"Bearer {0}".format(authtoken)}
    logging.info('Importing {0}... to {1}'.format(filters, url))
    # Iterate through the accounts schema and import each one
    x = 0
    for item in accountsJson["accounts"]:
        toImport = accountsJson["accounts"][x]
        # Grab just the account name for logging use later
        accountName = toImport["name"]
        # Get the extracted JSON into a format we can send via an HTTP request
        # that UCP will accept
        try:
            r = requests.post(
                url+'/accounts/',
                headers=headers,
                json=json.dumps(toImport),
                verify=False)
        # If the account already exists just pass, but tell the user
        except requests.exceptions.HTTPError as e:
            if e.code == 404:
                coolbeans
        # If we get any form of timeout we'll just retry
        except requests.exceptions.ConnectTimeout as e:
            logging.error('Failed to add {0} account to UCP {1}: {2}'.format(
                                                                      accountName,
                                                                      url, e))
            retries+=1
            retry_this('UCP', 10, retries, 3, import_accounts(authtoken, url, accountsJson))
        logging.debug('Imported: {}'.format(accountName))
        x+=1
    logging.info('All accounts successfully imported')

"""
Given a UCP url, authtoken, and two json dumps, one which is the staleJson
obtained from get_accounts() and the second which is freshly obtained using
the authtoken against the UCP where import_accounts() was just ran, diff the
json dumps to ensure all accounts were actually copied over.
"""
def verify_import(authtoken, url, staleJson):

def main():
    # argument parsing
    parser = argparse.ArgumentParser(description='Generate a list of current \
            users from a given Docker UCP and copy them over to a new UCP.')
    parser.add_argument("-i",
                        "--interactive",
                        dest="interactiveMode",
                        action="store_true",
                        help="Use interactive mode")
    parser.add_argument("--ucp-from",
                        dest="ucpOne",
                        help="Provide a UCP url for the first UCP environment \
                        where users will be copied from.")
    parser.add_argument("--ucp-to",
                        dest="ucpTwo",
                        help="Provide a UCP url for the second UCP environment \
                        where users will be copied to.")
    parser.add_argument("--ucp-from-user",
                        dest="ucpUser",
                        help="UCP admin username to use for the --from UCP")
    parser.add_argument("--ucp-from-password",
                        dest="ucpPassword",
                        help="UCP admin password to use for the --from UCP")
    parser.add_argument("--ucp-to-user",
                        dest="ucpUser",
                        help="UCP admin username to use for the --to UCP")
    parser.add_argument("--ucp-to-password",
                        dest="ucpPassword",
                        help="UCP admin password to use for the --to UCP")
    parser.add_argument("--skip-user-verify",
                        dest="skipVerify",
                        action="store_true",
                        help="Skip user verification of pulled account list \
                        from the --from UCP.")
    parser.add_argument("-D",
                        "--debug",
                        dest="debug",
                        action="store_true",
                        help="Enable debugging")

    args = parser.parse_args()

    # basic logging
    if args.debug == False:
        logger = logging.getLogger(name=None)
        logging.basicConfig(format='%(levelname)s: %(message)s',
                            level=logging.INFO)
    else:
        logger = logging.getLogger(name=None)
        logging.basicConfig(format='%(levelname)s: %(message)s',
                            level=logging.DEBUG)

"""
Main
"""
if __name__ == '__main__':
    sys.exit(main())
