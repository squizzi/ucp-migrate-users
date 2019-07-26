#!/usr/bin/env python
# Migrate users from one Docker UCP to another
# Kyle Squizzato <kyle.squizzato@docker.com>

import argparse
import docker
import sys
import os
import re
import requests
import logging
import json
import getpass
import subprocess
import validators
import atexit
from time import sleep
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class DockerClient:
    def cli():
        # Try setting the highest API version then autocorrect based on err
        cli = docker.from_env(version="1.39")
        try:
            cli.info()
        except docker.errors.APIError as err:
            # Check for API version mismatch and autocorrect
            if "400 Client Error" in str(err):
                # Extract correct API version to use and reload the cli to
                # that version instead
                # We can always assume the error will be identical since our
                # docker-py version is pinned, so we can extract it using
                # something simple like rsplit
                api_version = str(err).rsplit(' ', 1)[-1][0:4]
                # Once the api_version is extracted, set cli correctly
                cli = docker.from_env(version=api_version)
                return cli
            else:
                logging.error("Unable to determine client API version: {0}".format(err))
                sys.exit(1)
        except requests.exceptions.ConnectionError as err:
            if "Connection aborted" in str(err):
                logging.error("No docker socket found, please re-run with '-v /var/run/docker.sock:/var/run/docker.sock'")
                sys.exit(1)
            else:
                logging.error("Unable to connect to Docker CLI: {0}".format(err))
                sys.exit(1)
        return cli

""" Yes or no prompting """
def yes_no(question):
    yes = set(['yes','y'])
    no = set(['no','n'])
    prompt = " [Yes / No] "
    while True:
        print(question + '?' + prompt)
        choice = input().lower()
        if choice == '':
            # If no choice is given, return no
            return False
        if choice in no:
            return False
        if choice in yes:
            return True
        else:
           print("\nPlease respond with 'yes' or 'no'")

"""
run is a helper function for running shell and optionally:
* Returning output
* Checking for errors

It returns the output in bytes.

For simple shell runs that don't require error checking or further
processing use the shell library.
"""
def run(command, output=True, errors=True):
    sh = subprocess.run('{0}'.format(command), shell=True, capture_output=True)
    if output:
        return sh.stdout
    if errors:
        try:
            sh.check_returncode()
        except subprocess.CalledProcessError as err:
            logging.error("Command: {0} failed with error: {1}: {2}".format(command, err, sh.stderr))
            raise RuntimeError
        # If there's no error code do a secondary check for an error string
        if "An error occurred" in str(sh.stdout):
            logging.error("Command: {0} failed with error: {1}".format(sh.stdout))
            raise RuntimeError

"""
polling_retry provides retrying for error handling with retry time.
* Specify componentName which is breaking to provide logging.
* retrySecs is the number of seconds each retry will wait before starting
again.
* retryCount specifies the number of retries to be attempted before giving up
* doSomething handles what function to retry on each iteration
"""
def polling_retry(componentName, retrySecs, retryCount, doSomething):
    if retryCount == 0:
        # We've depleted our retries time to give up
        ('Unable to access {0} after {1} connection attempts, exiting'.format(componentName, maxAttempts))
        sys.exit(1)
    if retryCount > 0:
        logging.info('Unable to access {0}, attempting to reconnect to {0} in {1} seconds'.format(componentName, retrySecs))
        sleep(retrySecs)
        logging.info("Attempting to reconnect to {0} -- {1} retries remaining".format(componentName, retryCount))
        # Call a desired function.  Ensure the retryCount is passed into the
        # function so future iterations of polling_retry understand where to
        # end.
        return doSomething

"""
Log when we exit
"""
def exit_handler():
    logging.info('Exited!')

"""
Get and return an authtoken from a given UCP URL
"""
def get_ucp_token(username, password, url, retryCount=3):
    data='{{"username":"{0}","password":"{1}"}}'.format(username, password)
    logging.info('Authenticating with UCP {0}...'.format(url))
    try:
        r = requests.post(
            url+'/auth/login',
            data=data,
            verify=False)
    except requests.exceptions.RequestException as err:
        logging.error('Failed to authenticate with UCP {0}: {1}'.format(url, err))
        retryCount -= 1
        polling_retry("UCP Authtoken", 15, retryCount, get_ucp_token(username, password, url, retryCount))
    logging.debug('Got response: {0}'.format(r.text))
    if "unauthorized" in r.text:
        logging.error('Unable to authenticate with UCP {0}, are the admin credentials correct?'.format(url))
        sys.exit(1)
    a = json.loads(r.text)
    try:
        token = str(a["auth_token"])
    except KeyError:
        logging.error('No authtoken was received from UCP {0}'.format(url))
        sys.exit(1)
    return token

"""
Get a JSON dump of users or orgs from the local ucp-auth-store.

Then, ask the user to verify if the pulled information looks sane if True.
"""
def get_accounts(verifyUser=False, cli=DockerClient.cli()):
    # Do some initial setup for get_accounts, grab the rethinkcli needed to
    # perform the account fetching
    try:
        cli.images.pull('squizzi/rethinkcli-ucp:latest')
    except docker.errors.APIError as err:
        logging.error("Unable to pull squizzi/rethinkcli-ucp:latest: {0}".format(err))
        sys.exit(1)
    logging.info('Generating a list of accounts from local ucp-auth-store...')
    # Get the db addr to form the request
    try:
        db_addr = cli.info()["Swarm"]["NodeAddr"]
        logging.debug("Determined ucp-auth-store NodeAddr of {0}".format(db_addr))
    except docker.errors.APIError as err:
        logging.error("Unable to determine ucp-auth-store database address")
        sys.exit(1)
    # Dump the accounts from the db using the obtained db_addr
    reql_command = "r.db('enzi').table('accounts').pluck('name', 'id', 'fullName', 'isOrg', 'isAdmin', 'isActive', 'isImported', 'membersCount', 'teamsCount')"
    try:
        account_dump = run("echo \"{0}\" | docker run --rm -i -e DB_ADDRESS={1} -v ucp-auth-api-certs:/tls squizzi/rethinkcli-ucp non-interactive; echo".format(reql_command, db_addr))
    except RuntimeError as e:
        logging.error("Unable to dump accounts from ucp-auth-store: {0}".format(e))
        sys.exit(1)
    logging.info('Getting ready to import the following accounts:\n')
    # Using the captured information send a list of captured accounts out to
    # the user
    try:
        a = json.loads(account_dump)
    except json.decoder.JSONDecodeError:
        logging.error("Unable to parse json account listing from ucp-auth-store")
        sys.exit(1)
    print(json.dumps(a, indent=4, sort_keys=True))
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
def import_accounts(authtoken, url, accountsJson, userPassword='changeme', retryCount=3):
    headers = {
        "Authorization":"Bearer {0}".format(authtoken),
        "Content-Type":"application/json"
    }
    logging.info('Importing accounts to {0}'.format(url))
    # Iterate through the accounts schema and import each one
    x = 0
    for item in accountsJson:
        # If the account is a user, update the dict with the password entry
        password_dict = {
            "password":"{0}".format(userPassword)
        }
        if not accountsJson[x]["isOrg"]:
            accountsJson[x].update(password_dict)
        # Grab just the account name for logging use later
        accountName = accountsJson[x]["name"]
        # Add the account to the UCP
        toImport = json.dumps(accountsJson[x])
        try:
            r = requests.post(
                url+'/accounts/',
                headers=headers,
                data=toImport,
                verify=False)
        # If we get any form of exception from requests we'll just retry
        except requests.exceptions.RequestException as e:
            logging.error('Failed to add {0} account to UCP {1}: {2}'.format(accountName, url, e))
            retryCount -= 1
            polling_retry("Import accounts", 15, 3, import_accounts(authtoken, url, accountsJson, retryCount))
        # If the account already exists just pass, but tell the user
        if "ACCOUNT_EXISTS" in r.text:
            logging.info('Cannot import {0}, account already exists, skipping'.format(accountName))
            logging.debug(r.text)
        if r.status_code is 400:
            logging.debug("Unable to import {0}, received HTTP Bad Request Error: {0}".format(accountName, r.text))
        logging.info('Imported: {}'.format(accountName))
        x+=1

def main():
    # argument parsing
    parser = argparse.ArgumentParser(description="Generate a list of current \
            accounts from the local Docker UCP's enzi database and copy them \
            over to a new UCP.")
    parser.add_argument("-i",
                        "--interactive",
                        dest="interactiveMode",
                        action="store_true",
                        help="Use interactive mode")
    parser.add_argument("--ucp-to",
                        dest="ucpTwo",
                        help="Provide a UCP url for the second UCP environment \
                        where users will be copied to.")
    parser.add_argument("--ucp-to-user",
                        dest="ucpUserTwo",
                        help="UCP admin username to use for the UCP users will \
                        be copied to.")
    parser.add_argument("--ucp-to-password",
                        dest="ucpPasswordTwo",
                        help="UCP admin password to use for the UCP users will \
                        be copied to.")
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
            args.ucpTwo = input('Enter UCP URL where accounts will be copied TO: ')
            if not validators.url(args.ucpTwo):
                logging.error('Please enter a valid UCP URL (ex. https://example.com).')
            else:
                break
        while True:
            args.ucpUserTwo = input('UCP admin username: ')
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
            args.userPassword = input('Enter the default password for imported user accounts (8 or more characters): ')
            if not validators.length(args.userPassword, min=8):
                logging.error('Please enter a password that is 8 characters or longer.')
            else:
                break
        # if we're in interactiveMode we verifyUser=True, else we'll skip
        # user verification
        verify = True
    if None in (
        args.ucpTwo,
        args.ucpUserTwo,
        args.ucpPasswordTwo,
        args.userPassword
        ):
        logging.info('Flags: --ucp-to, --ucp-to-user, --ucp-to-password, -P are all required unless interactive mode is used.\n')
        parser.print_usage()
        sys.exit(1)

    """
    Account import
    """
    # Get a list of accounts using the local ucp-auth-store
    ucpOneAccountJson = get_accounts(verifyUser=verify)
    # Get an auth token against the --to UCP
    ucpTwoAuthToken = get_ucp_token(args.ucpUserTwo, args.ucpPasswordTwo, args.ucpTwo)
    # Import accounts into the --to UCP
    import_accounts(ucpTwoAuthToken, args.ucpTwo, ucpOneAccountJson, args.userPassword)
    # Tell the user we're done
    logging.info('Complete.')

"""
Main
"""
if __name__ == '__main__':
    atexit.register(exit_handler)
    sys.exit(main())
