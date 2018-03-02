#!/usr/bin/env python
# Migrate users from one Docker UCP to another
# Kyle Squizzato <kyle.squizzato@docker.com>

import argparse
import sys
import os
import re
import requests
import logging

"""
Get and return an authtoken from a given UCP URL
"""
def get_token(username, password, url):
    #data = "{username': 'admin', 'password': 'dockerucp'}"
    data='{{"username":"{0}","password":"{1}"}}'.format(username, password)
    r = requests.post(
        url+'/auth/login',
        data=data,
        verify=False)
    a = json.loads(r.text)
    token = str(a["auth_token"])
    return token

"""
Get a list of users and orgs from a given UCP URL.  Facilitated by the
/accounts endpoint.
"""
def get_accounts(authtoken, url, limit=1000):
    headers = '{{"Authorization":"Bearer {0}"}}'.format(authtoken)
    r = requests.get(
        '{0}/accounts/?filter=all&limit={1}'.format(url, limit),
        headers=headers
    )

def main():
    # argument parsing
    global args
    parser = argparse.ArgumentParser(description='Generate a list of current \
            users from a given Docker UCP and copy them over to a new UCP.')
    parser.add_argument("--from",
                        dest="ucp_one",
                        help="Provide a UCP url for the first UCP environment \
                        where users will be copied from.",
                        required=True)
    parser.add_argument("--to",
                        dest="ucp_two",
                        help="Provide a UCP url for the second UCP environment \
                        where users will be copied to.",
                        required=True)
    parser.add_argument("-D",
                        "--debug",
                        dest="debug",
                        action="store_true",
                        help="Enable debugging")

    args = parser.parse_args()

    # logging
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
