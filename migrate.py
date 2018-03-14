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
import validators
import atexit
from jsondiff import diff
from time import sleep
from requests.packages.urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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
    logging.debug('Got response: {}'.format(r.text))
    if "unauthorized" in r.text:
        logging.error('Unable to authenticate with UCP {}, are the admin credentials correct?'.format(url))
        sys.exit(1)
    a = json.loads(r.text)
    try:
        token = str(a["auth_token"])
    except KeyError:
        logging.error('No authtoken was received from UCP {0}'.format(url))
        sys.exit(1)
    return token

"""
Get a JSON dump of users or orgs from a given UCP URL, facilitated by the
/accounts/ endpoint.  Use customFilter for custom filters, if desired, else
we will just pull 'all'.

Then, ask the user to verify if the pulled information looks sane if True.
"""
def get_accounts(authtoken, url, customFilter='all', verifyUser=False):
    headers = {"Authorization":"Bearer {0}".format(authtoken)}
    logging.info('Generating a list of accounts from {0}...'.format(url))
    # Make the request
    try:
        r = requests.get(
            '{0}/accounts/?filter={1}&limit=1000'.format(url, customFilter),
            headers=headers,
            verify=False
        )
    except requests.exceptions.RequestException as e:
        logging.error('Failed to get account list for UCP {0}: {1}'.format(url, e))
        retries+=1
        retry_this('UCP', 10, retries, 3, get_accounts(authtoken, url, customFilter, verifyUser))
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
        return a

"""
Import a given JSON dump of accounts into a given UCP URL.  Give users a
default password of 'changeme'.  Password is configurable.
"""
def import_accounts(authtoken, url, accountsJson, userPassword='changeme'):
    headers = {
        "Authorization":"Bearer {0}".format(authtoken),
        "Content-Type":"application/json"
    }
    logging.info('Importing accounts to {0}'.format(url))
    # Setup a default password for users
    password_dict = {u'password':u'{0}'.format(userPassword)}
    # Iterate through the accounts schema and import each one
    for x in range(len(accountsJson["accounts"])):
        if not accountsJson["accounts"][x]["isOrg"]:
            accountsJson["accounts"][x].update(password_dict)
        toImport = accountsJson["accounts"][x]
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
            pass
        logging.info('Imported: {}'.format(accountName))
        logging.debug(toImport)
        x+=1
    logging.info('All accounts successfully imported')

"""
Given a UCP url, authtoken, and two json dumps, one which is the staleJson
obtained from get_accounts() and the second which is freshly obtained using
the authtoken against the UCP where import_accounts() was just ran, diff the
json dumps to ensure all accounts were actually copied over.
"""
##FIXME: This is currently unreliable, need to fix this for a future release
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
                        dest="ucpUserTwo",
                        help="UCP admin username to use for the --to UCP")
    parser.add_argument("--ucp-to-password",
                        dest="ucpPasswordTwo",
                        help="UCP admin password to use for the --to UCP")
    parser.add_argument("-P",
                        "--user-password",
                        dest="userPassword",
                        help="The default password on newly imported user \
                        accounts.")
    parser.add_argument("-D",
                        "--debug",
                        dest="debug",
                        action="store_true",
                        help="Enable debugging")
    #TODO: Implement customFilter support

    args = parser.parse_args()

    # basic logging
    if not args.debug:
        logger = logging.getLogger(name=None)
        logging.basicConfig(format='%(levelname)s: %(message)s',
                            level=logging.INFO)
    else:
        logger = logging.getLogger(name=None)
        logging.basicConfig(format='%(levelname)s: %(message)s',
                            level=logging.DEBUG)

    """
    Flag Verification
    """
    # Ask user whether we should enter interactiveMode or not
    if args.interactiveMode:
        # build a list of inputs from the arguments and apply those to
        # the argparse vars for backwards compatability
        while True:
            args.ucpOne = raw_input('Enter UCP where accounts will be copied FROM: ')
            if not validators.url(args.ucpOne):
                logging.error('Please enter a valid UCP URL (ex. https://example.com).')
            else:
                break
        while True:
            args.ucpUserOne = raw_input('UCP admin username: ')
            if not validators.length(args.ucpUserOne, min=1):
                logging.error('Please enter an admin username.')
            else:
                break
        while True:
            args.ucpPasswordOne = getpass.getpass('UCP admin password: ')
            if not validators.length(args.ucpPasswordOne, min=8):
                logging.error('Please enter a valid password.')
            else:
                break
        while True:
            args.ucpTwo = raw_input('Enter UCP where accounts will be copied TO: ')
            if not validators.url(args.ucpTwo):
                logging.error('Please enter a valid UCP URL (ex. https://example.com).')
            else:
                break
        while True:
            args.ucpUserTwo = raw_input('UCP admin username: ')
            if not validators.length(args.ucpUserTwo, min=1):
                logging.error('Please enter an admin username.')
            else:
                break
        while True:
            args.ucpPasswordTwo = getpass.getpass('UCP admin password: ')
            if not validators.length(args.ucpPasswordTwo, min=8):
                logging.error('Please enter a valid password.')
            else:
                break
        while True:
            args.userPassword = raw_input('Enter the default password for imported user accounts (8 or more characters): ')
            if not validators.length(args.userPassword, min=8):
                logging.error('Please enter a password that is 8 characters or longer.')
            else:
                break
        # if we're in interactiveMode we verifyUser=True, else we'll skip
        # user verification
        verify = True
    if None in (
        args.ucpOne,
        args.ucpUserOne,
        args.ucpPasswordOne,
        args.ucpTwo,
        args.ucpUserTwo,
        args.ucpPasswordTwo,
        args.userPassword
        ):
        logging.info('Flags: --ucp-from, --ucp-to, --ucp-from-user, --ucp-from-password, --ucp-to-user, --ucp-to-password, -P are all required unless interactive mode is used.\n')
        parser.print_usage()
        sys.exit(1)

    """
    Account import
    """
    # Get an auth token against the --from UCP
    ucpOneAuthtoken = get_token(args.ucpUserOne, args.ucpPasswordOne, args.ucpOne)
    # Get a list of accounts against the --from UCP
    ucpOneAccountJson = get_accounts(ucpOneAuthtoken, args.ucpOne, verifyUser=verify)
    # Get an auth token against the --to UCP
    ucpTwoAuthToken = get_token(args.ucpUserTwo, args.ucpPasswordTwo, args.ucpTwo)
    # Import accounts into the --to UCP
    import_accounts(ucpTwoAuthToken, args.ucpTwo, ucpOneAccountJson, args.userPassword)
    # Tell the user we're done
    logging.info('Complete.')

"""
Main
"""
if __name__ == '__main__':
    sys.exit(main())
