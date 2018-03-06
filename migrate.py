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
import getpass
from jsondiff import diff
from time import sleep


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
/accounts/ endpoint.  Use customFilter for custom filters, if desired, else
we will just pull 'all'.

Then, ask the user to verify if the pulled information looks sane.
"""
def get_accounts(authtoken, url, customFilter='all', verifyUser=True):
    headers = {"Authorization":"Bearer {0}".format(authtoken)}
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
        retry_this('UCP', 10, retries, 3, get_accounts(authtoken, url, users, customFilter, verifyUser))
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
def import_accounts(authtoken, url, accountsJson, userPassword):
    headers = {
        "Authorization":"Bearer {0}".format(authtoken),
        "Content-Type":"application/json"
    }
    logging.info('Importing {0}... to {1}'.format(filters, url))
    # Give each user a default configurable userPassword
    if userPassword == None:
        userPassword = 'changeme'
    # Iterate through the accounts schema and import each one
    x = 0
    for item in accountsJson["accounts"]:
        # If the account is a user, update the dict with the password entry
        if accountsJson["accounts"][x]["isOrg"] == False:
            toImport = accountsJson["accounts"][x].update({u'password': userPassword})
        else:
            toImport = accountsJson["accounts"][x]
        # Get the extracted JSON into a format we can send via an HTTP request
        # that UCP will accept
        # Grab just the account name for logging use later
        accountName = toImport["name"]
        # Add the account to the UCP
        try:
            r = requests.post(
                url+'/accounts/',
                headers=headers,
                data=json.dumps(toImport),
                verify=False)
        # If we get any form of exception from requests we'll just retry
        except requests.exceptions.RequestException as e:
            logging.error('Failed to add {0} account to UCP {1}: {2}'.format(accountName, url, e))
            retries+=1
            retry_this('UCP', 10, retries, 3, import_accounts(authtoken, url, accountsJson))
        # If the account already exists just pass, but tell the user
        if "ACCOUNT_EXISTS" in r.text:
            logging.info('Cannot import {0}, account already exists'.format(accountName))
            logging.debug(r.text)
        logging.debug('Imported: {}'.format(accountName))
        x+=1
    logging.info('All accounts successfully imported')

"""
Given a UCP url, authtoken, and two json dumps, one which is the staleJson
obtained from get_accounts() and the second which is freshly obtained using
the authtoken against the UCP where import_accounts() was just ran, diff the
json dumps to ensure all accounts were actually copied over.
"""
def verify_import(authtoken, url, staleJson, customFilter='all'):
    headers = {"Authorization":"Bearer {0}".format(authtoken)}
    freshJson = get_accounts(authtoken, url, customFilter, verifyUser=False)
    # If we detect differences then we'll log those and exit
    # TODO: We don't really do anything more here, perhaps we can retry the
    # differences?
    diffedJson = diff(staleJson, freshJson)
    if diffedJson != {}:
        logging.error('Newly imported accounts list on {0} does not match existing {1} list'.format(url, customFilter))
        logging.debug(diffedJson)
        return False
    else:
        return True

def main():
    # argument parsing
    parser = argparse.ArgumentParser(description='Generate a list of current \
            accounts from a given Docker UCP and copy them over to a new UCP.')
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
                        dest="ucpUserOne",
                        help="UCP admin username to use for the --from UCP")
    parser.add_argument("--ucp-from-password",
                        dest="ucpPasswordOne",
                        help="UCP admin password to use for the --from UCP")
    parser.add_argument("--ucp-to-user",
                        dest="ucpUserOne",
                        help="UCP admin username to use for the --to UCP")
    parser.add_argument("--ucp-to-password",
                        dest="ucpPasswordOne",
                        help="UCP admin password to use for the --to UCP")
    parser.add_argument("-P",
                        "--user-password",
                        dest="userPassword",
                        help="The default password on newly imported user ")
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
    #TODO: Implement customFilter support

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

    # Ask user whether we should enter interactiveMode or not
    if interactiveMode:
        # build a list of inputs from the arguments and apply those to
        # the argparse vars for backwards compatability
        args.ucpOne = raw_input('Enter UCP where accounts will be copied FROM:')
        args.ucpUserOne = raw_input('UCP admin username:')
        args.ucpPasswordOne = getpass.getpass('UCP admin password')
        args.ucpTwo = raw_input('Enter UCP where accounts will be copied TO:')
        args.ucpUserTwo = raw_input('UCP admin username:')
        args.ucpPasswordTwo = getpass.getpass('UCP admin password')
        args.userPassword = raw_input('Enter the default password for imported user accounts:')
    # If the user didn't prepend https:// to their UCP fqdn's we'll do it for
    # them
    if not "https://" in args.ucpOne:
        args.ucpOne = "https://" + args.ucpOne
    if not "https://" in args.ucpTwo:
        args.ucpTwo = "https://" + args.ucpTwo
    # Get an auth token against the --from UCP
    ucpOneAuthtoken = get_token(args.ucpUserOne, args.ucpPasswordOne, args.ucpOne)
    # Get a list of accounts against the --from UCP
    ucpOneAccountJson = get_accounts(ucpOneAuthtoken, args.ucpOne, verifyUser=args.skipVerify)
    # Get an auth token against the --to UCP
    ucpTwoAuthToken = get_token(args.ucpUserTwo, args.ucpPasswordTwo, args.ucpTwo)
    # Import accounts into the --to UCP
    import_accounts(ucpTwoAuthToken, args.ucpTwo, ucpOneAccountJson, args.userPassword)
    # Verify that everything looks good
    verify_import(ucpTwoAuthToken, args.ucpTwo, ucpOneAccountJson)
    # Tell the user we're done
    logging.info('Complete.')

"""
Main
"""
if __name__ == '__main__':
    sys.exit(main())
