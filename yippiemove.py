#! /usr/bin/env python
# -*- coding: utf8 -*-

"""
Command-line interface for the YippieMove API.
"""

import argparse
import json
import operator
import os
import sys
import time
from base64 import b64encode
from getpass import getpass
from urllib import urlencode
from urlparse import urlparse
from urlparse import urljoin

import requests
import logbook

API_ACCESS_TOKEN = None  # --token=ceaba709b1
API_SERVER = None

VERSION = "0.1"

"""

To override the API URL, simply run:
$ export YIPPIEMOVE_API="https://api.sandbox.yippiemove.com/v1"

"""
DEFAULT_API_SERVER = os.getenv("YIPPIEMOVE_API", "https://api.yippiemove.com/v1")
OAUTH_AUTHORIZE_URL = "%s://%s/oauth2/authorize"
OAUTH_ACCESS_CODE_URL = "%s://%s/oauth2/code/"
OAUTH_TOKEN_URL = "%s://%s/oauth2/token/"

VERIFY_SSL = True


################################################################
# Utilities
################################################################

def url(*path):
    return url_path_join(API_SERVER, *path)


def url_path_join(*parts):
    """Join the parts of the URL. If any part begins with /, assume it's an absolute URL."""

    if len(parts) == 1 or not parts[1]:
        return parts[0]

    if parts[1][0] == '/':
        return url_path_join(urljoin(parts[0], parts[1]), *parts[2:])
    elif parts[0][-1] == '/':
        return url_path_join("".join(parts[:2]), *parts[2:])
    else:
        return url_path_join("/".join(parts[:2]), *parts[2:])


def convert_arg_strings_to_dict(args):

    if isinstance(args, dict):
        return args

    dictionary = {}
    for arg in args:
        pieces = arg.split("=")
        if len(pieces) != 2:
            raise Exception("Invalid arguments.")
        dictionary[pieces[0]] = pieces[1]
    return dictionary


def check_requirements(required, args):
    for r in required:
        if not r in args:
            raise BadRequestException("You must specify %s." % r)


def get_oauth_url_for(method):
    """Returns the OAuth2 URLs we need based on the given API_SERVER."""

    parsed = urlparse(API_SERVER)
    scheme = parsed.scheme
    domain_pieces = parsed.netloc.split(".")

    if domain_pieces[0] == "api":
        domain_pieces = domain_pieces[1:]

    netloc = ".".join(domain_pieces)

    if method == "authorize":
        return OAUTH_AUTHORIZE_URL % (scheme, netloc)
    elif method == "access_code":
        return OAUTH_ACCESS_CODE_URL % (scheme, netloc)
    elif method == "token":
        return OAUTH_TOKEN_URL % (scheme, netloc)
    else:
        return ""


def uri_for_resource(object_type, object_id=None, args=[]):
    """Given an object type, an optional ID, and optional
    args, construct its URI to speaking to the server
    about the object."""

    if object_type == "order":
        GET_URL = "users/current/orders/%s/" % object_id

    elif object_type == "user":
        GET_URL = "users/%s/" % object_id

    elif object_type == "move_job":
        GET_URL = "users/current/move_jobs/%s/" % object_id

    elif object_type == "payment":
        GET_URL = "users/current/orders/%s/payment/" % object_id

    elif object_type == "batch":
        GET_URL = "users/current/batches/%s/" % object_id

    elif object_type == "email_account":
        GET_URL = "users/current/move_jobs/1/accounts/%s/" % object_id

    elif object_type == "provider":
        GET_URL = "providers/%s/" % object_id

    else:  # if object_type is unknown, return None
        return None

    return GET_URL


def introspect_dictionary_for_uris(dictionary):
    """Accepts a dictionary and introspects it to discover
    keys which are object references, and attempts to
    replace them with the URI of the object they represent."""

    for key, value in dictionary.items():
        replacement = uri_for_resource(key, value)
        if replacement is not None:
            dictionary[key] = replacement


def get_terminal_size():
    try:
        size = os.popen('stty size', 'r').read().split()
    except:
        size = (40, 78)
    return {'width': int(size[1]), 'height': int(size[0])}


################################################################
# Exceptions
################################################################

class ForbiddenException(Exception):
    """Exception caused when the user does not have
    permission to perform the action they've requested."""
    pass


class NotAuthenticatedException(Exception):
    """Exception caused when a user is not
    authenticated when trying to access the API
    or their token is invalid."""
    pass


class NotFoundException(Exception):
    """Exception caused when an object or objects the
    user has requested could not be found."""
    pass


class ServerErrorException(Exception):
    """Exception caused by a server error on YippieMove's server."""
    pass


class MethodNotAllowedException(Exception):
    """Exception caused when the user attempts to peform an
    HTTP verb on the server that is not allowed."""
    pass


class BadRequestException(Exception):
    """Exception caused by invalid input to the API."""

    def __init__(self, errors=[]):
        self.errors = errors


class ConflictException(Exception):
    """Exception caused by a data conflict on the server."""
    pass


class NotEnoughCreditsException(Exception):
    """Exception caused by trying to do something on the
    server for which you haven't sufficient credits."""
    pass


################################################################
# HTTP requests, authentication, and response handling
################################################################

class HTTPBasicAuth(requests.auth.AuthBase):
    """"""

    def __init__(self, type_="Bearer", data=""):
        self.data = data
        self.type = type_

    def __call__(self, r):
        r.headers['Authorization'] = "%s %s" % (self.type, self.data)
        return r


def make_request(url, method="GET", data={}):
    func = getattr(requests, method.lower())
    auth = HTTPBasicAuth(data=API_ACCESS_TOKEN)

    # print url
    # return

    response = func(url, auth=auth, data=data, verify=VERIFY_SSL)
    try:
        response_json = json.dumps(json.loads(response.content))
    except:
        response_json = response.content

    logbook.debug("%s %s\n%s\n%s" % (method, url, json.dumps(data), response_json))

    if response.status_code == 200:
        return response

    elif response.status_code == 400:
        raise BadRequestException(response.json['description'])

    elif response.status_code == 401:

        if response.json['error'] == "Not authenticated.":
            raise NotAuthenticatedException()
        elif response.json['description'] == "You don't have enough credits to pay for this order.":
            raise NotEnoughCreditsException()
        else:
            raise ForbiddenException()

    elif response.status_code == 404:
        raise NotFoundException()

    elif response.status_code == 405:
        raise MethodNotAllowedException()

    elif response.status_code == 409:
        raise ConflictException(response.json['description'])

    elif response.status_code == 500:
        # print response.content
        raise ServerErrorException()


def get(url, data={}):
    response = make_request(url=url, method="GET", data=data)
    return response


def post(url, data={}):
    response = make_request(url=url, method="POST", data=data)
    return response


def put(url, data={}):
    response = make_request(url=url, method="PUT", data=data)
    return response


def delete(url):
    response = make_request(url=url, method="DELETE")
    return response


################################################################
# CRUD methods
################################################################

def create(object_type, args=[]):
    """Handle the creation of an object."""

    args = convert_arg_strings_to_dict(args)

    if object_type == "order":
        CREATE_URL = "users/current/orders/"

    elif object_type == "move_job":
        CREATE_URL = "users/current/move_jobs/"

    elif object_type == "payment":
        check_requirements(["order"], args)
        CREATE_URL = "users/current/orders/%s/payment/" % args['order']

    elif object_type == "batch":
        CREATE_URL = "users/current/batches/"

    elif object_type == "email_account":
        check_requirements(["move_job"], args)
        CREATE_URL = "users/current/move_jobs/%s/accounts/" % args['move_job']

    elif object_type == "email_folder":
        check_requirements(["email_account"], args)
        CREATE_URL = "users/current/move_jobs/1/accounts/%s/email_folders/" % args['email_account']
        del args['email_account']

    elif object_type == "email_job":
        check_requirements(["move_job"], args)
        CREATE_URL = "users/current/move_jobs/%s/email_part/" % args['move_job']

    elif object_type == "component_job":
        check_requirements(["job_type", "move_job"], args)
        CREATE_URL = "users/current/move_jobs/%s/%s_part/" % (args['move_job'], args['job_type'])
        del args["job_type"]

    introspect_dictionary_for_uris(args)

    response = post(url=url(CREATE_URL), data=args)

    return response.content


def read(object_type, object_id, args=[]):
    """Handle the read of an object."""

    args = convert_arg_strings_to_dict(args)

    GET_URL = uri_for_resource(object_type, object_id=object_id, args=args)

    response = get(url="%s?%s" % (url(GET_URL), urlencode(args)))
    return response.content


def update(object_type, args, object_id):
    """Handle the updating of an object."""

    args = convert_arg_strings_to_dict(args)

    UPDATE_URL = uri_for_resource(object_type, object_id=object_id, args=args)

    if UPDATE_URL is None:  # special cases

        if object_type == "email_job":
            check_requirements(["move_job"], args)
            UPDATE_URL = "users/current/move_jobs/%s/email_part/"

        elif object_type == "component_job":
            check_requirements(["move_job", "job_type"], args)
            UPDATE_URL = "users/current/move_jobs/%s/%s_part/" % (args['move_job'], args['job_type'])
            del args["job_type"]

        elif object_type == "email_folder":
            check_requirements(["move_job", "email_account"], args)
            UPDATE_URL = "users/current/move_jobs/%s/accounts/%s/email_folders/%s/" % (args['move_job'], args['email_account'], object_id)
            del args["move_job"]
            del args["email_account"]

    introspect_dictionary_for_uris(args)
    put(url=url(UPDATE_URL), data=args)
    logbook.info("%s with id %s was updated." % (object_type, object_id))


def remove(object_type, object_id, args=[]):
    """Handle the deletion of an object."""

    args = convert_arg_strings_to_dict(args)

    if object_type == "order":
        DELETE_URL = "users/current/orders/%s/" % object_id

    elif object_type == "move_job":
        DELETE_URL = "users/current/move_jobs/%s/" % object_id

    elif object_type == "email_account":
        check_requirements(["move_job"], args)
        DELETE_URL = "users/current/move_jobs/%s/accounts/%s/" % (args['move_job'], object_id)

    delete(url=url(DELETE_URL))
    logbook.info("Deleted %s with id %s." % (object_type, object_id))


def list_objects(object_type, args=[]):
    """Lists all the current user's objects of a given type."""

    args = convert_arg_strings_to_dict(args)

    if object_type == "order":
        LIST_URL = "users/current/orders/"

    elif object_type == "move_job":
        args['expand'] = "move_job"
        LIST_URL = "users/current/move_jobs/"

    elif object_type == "email_folder":
        check_requirements(["move_job", "email_account"], args)
        LIST_URL = "users/current/move_jobs/%s/accounts/%s/email_folders/" % (args['move_job'], args['email_account'])

    elif object_type == "provider":
        LIST_URL = "providers/"

    elif object_type == "email_account":
        check_requirements(["move_job"], args)
        LIST_URL = "users/current/move_jobs/%s/accounts/" % args['move_job']

    response = get(url=url("%s?%s" % (LIST_URL, urlencode(args))))
    return response.content


################################################################
# Specialty methods
################################################################

def raw_status(object_type, object_id):

    if object_type == "order":
        pass
    elif object_type == "move_job":
        URL = "users/current/move_jobs/%s/status/" % object_id
        try:
            response = get(url(URL))
            return response.json
        except:
            return {}


def status(object_type, object_id):
    """Prints a pretty status of an object, given its type and ID."""

    if object_type == "order":

        ORDER_URL = "users/current/orders/%s/" % object_id
        USER_URL = "users/current/"
        MOVE_JOBS_URL = "users/current/move_jobs/?order=%s&expand=move_job" % object_id

        order = get(url=url(ORDER_URL)).json
        user = get(url=url(USER_URL)).json
        move_jobs = get(url=url(MOVE_JOBS_URL)).json

        print
        print "=" * 64
        print "  Status of Order #%d" % order['id']
        print "=" * 64
        print "  Owner: %s" % user['username']
        print "  This order has been paid for." if len(order['payments']) else "  This order has not been paid for."
        print
        print "  Move Jobs on this Order:"

        if len(move_jobs):
            for job in move_jobs:
                print "    -MoveJob #%s" % job['id']
                data = raw_status("move_job", job['id'])
                print "     %s" % data['overall']['status_message']
        else:
            print "    -None"
        print

    elif object_type == "move_job":
        data = raw_status("move_job", object_id)
        print data
        print
        print "=" * 64
        print "  Status of MoveJob #%s" % object_id
        print "=" * 64
        print "  %s" % data['overall']['status_message']
        print


################################################################
# Wizards
################################################################

def wizard(action=None, args=[]):

    # If the args are passed in as a list (or aren't
    # at all) we need to convert it into a dictionary.
    if isinstance(args, list):
        args = convert_arg_strings_to_dict(args)

    current_user = get(url('users/current/')).json

    providers = get(url('providers/')).json
    providers = sorted(providers, key=operator.itemgetter('name'))

    def get_email_account_from_user(providers):
        other_choice = len(providers) + 1

        for i, provider in enumerate(providers):
            print "  %2d) %s" % (i + 1, provider['name'])

        print "  " + "==" * 16
        print "  %2d) Other" % other_choice
        print

        choice = -1
        while (choice < 1) or (choice > (len(providers) + 1)):
            try:
                choice = int(raw_input("  Your choice: "))
            except ValueError:
                print "  Choice must be an integer."
                continue

        if choice == other_choice:
            print "  You've chosen Other. Please tell us about the Other email server:\n"
            selected_provider = {}
            selected_provider['host'] = raw_input("    Hostname: ")
            selected_provider['port'] = int(raw_input("        Port: "))
            selected_provider['ssl'] = bool(True if raw_input("  SSL? [y/n]: ") in ["y", "Y"] else False)
        else:
            selected_provider = providers[choice - 1]
            print "  You've chosen %s" % selected_provider['name']

        print
        selected_provider['login'] = raw_input("     Login: ")
        selected_provider['password'] = getpass("  Password: ")
        print

        return selected_provider

    def get_and_verify_email_account(move_job, account_type):

        okay = False

        while not okay:
            account = get_email_account_from_user(providers)

            account_data = {
                'move_job': move_job['link'],
                'login': account['login'],
                'password': account['password'],
                'port': account['port'],
                'host': account['host'],
                'ssl': account['ssl']
            }

            if 'id' in account:
                account_data['provider'] = account['identifier']

            email_account = put(url(move_job['link'], 'accounts/%s/' % account_type), account_data).json

            print "  Indexing email account..."

            # Wait for the account indexing to be accomplished or an error to occur

            while True:

                time.sleep(5)

                try:
                    status = get(url(move_job['link'], 'status/')).json
                except:
                    continue

                if account_type in status:
                    if status[account_type]['status_code'] == "account-error":
                        print "  Could not connect to the email account. Please double-check your credentials.\n"

                        # Credentials were wrong, let's remove that account so we
                        # don't have a surplus of wasted accounts
                        delete(url(email_account['link']))
                        time.sleep(2)
                        break

                    if status[account_type]['indexed']:
                        okay = True
                        break

        print "  %s email account has been indexed." % account_type.capitalize()
        return email_account

    def draw_columns(folders):
        longest_name = max([len(folder['name']) for folder in folders])
        longest_number = len(str(len(folders)))
        size = get_terminal_size()
        padding = 2

        columns = size['width'] / (longest_name + padding + longest_number + 2)
        string = "{0:%d}) {1:%s}" % (longest_number, longest_name)

        def chunks(folder_list, chunk_size):
            """Returns elements of the folder_list in
            chunks of chunk_size size."""
            for index in xrange(0, len(folder_list), chunk_size):
                yield folder_list[index:index + chunk_size]

        folder_no = 1

        for chunk in chunks(folders, columns):
            line = ""
            for i in range(len(chunk)):
                name = chunk[i]['destination_name'] if 'destination_name' in chunk[i] else chunk[i]['name']
                line += string.format(folder_no, name)
                folder_no += 1
                if (i + 1) != columns:
                    line += " " * padding
            print line

    def get_choice():
        print
        print "Example commands:"
        print "  \"skip 15\"          Marks folder number 15 to not be transferred."
        print "  \"rename 14 Family\" Rename a folder before transferring."
        print "  \"finished\"         Save changes and continue."

        while True:
            print
            choice = parse_choice(raw_input("> "))
            if choice:
                return choice
            else:
                print "Invalid choice. Please try again."

    def take_action(choice):
        """Accepts a choice returned from get_choice
        and executes the action it describes."""

        if choice is None:
            return

        action, folder_number, args = choice
        folder = folders[folder_number - 1]

        if action == "skip":
            # print "skip folder %d" % folder_number
            put(url(folder['link']), data={'selected': False})
            folders.remove(folder)
        elif action == "rename":
            # print "rename folder %d to %s" % (folder_number, " ".join(args))
            put(url(folder['link']), data={'destination_name': " ".join(args)})
            folder['destination_name'] = " ".join(args)

    def parse_choice(choice):
        """Accepts the raw input from the user and parses
        the choice into an action to take, returning it.
        If an action cannot be determined, return None,
        otherwise, format is as follows:

        ([action_name], [folder_number], [optional_args])

        """

        choice = choice.split(" ")

        if choice[0] not in ["skip", "rename", "finished"]:
            return None

        if choice[0] == "finished":
            return (choice[0], None, None)

        try:
            action, folder_number = choice[0], int(choice[1])
        except:
            return None

        return (action, folder_number, choice[2:] if len(choice) > 2 else None)

    new_order = post(url(current_user['link'], 'orders/')).json
    new_move_job = post(url(current_user['link'], 'move_jobs/'), {'order': new_order['link']}).json

    print
    print "=" * 64
    print "  Step 1: Where are we moving from?"
    print "=" * 64
    print

    source_email_account = get_and_verify_email_account(new_move_job, "source")

    print
    print "=" * 64
    print "  Step 2: Where to?"
    print "=" * 64
    print

    get_and_verify_email_account(new_move_job, "destination")

    print
    print "=" * 64
    print "  Step 3: What to transfer"
    print "=" * 64
    print

    folders = get(url(source_email_account['link'], 'email_folders/')).json

    print "  Below are the folders found in your source email account."
    print "  You may make changes by following the commands below. When"
    print "  you're done, enter 'finished' and press enter."

    while True:
        print
        draw_columns(folders)
        choice = get_choice()
        if choice[0] == "finished":
            break
        else:
            take_action(choice)

    print "  Folders saved."

    # We now officially have enough information to constitute an EmailJob.
    post(url(new_move_job['link'], 'email_part/'), data={'move_job': new_move_job['link']})

    print
    print "=" * 64
    print "  Step 4: Make payment"
    print "=" * 64
    print

    # refresh the Order
    new_order = get(url(new_order['link'])).json

    # Offer option to pay for Order now, or give Order number to allow them to pay later.
    print "  To begin your order you must pay the full balance of"
    print "  the Order: %s credits." % new_order['credits']
    print

    pay_now = False

    while True:

        choice = raw_input("  Would you like to pay now? [Y/n]")

        if len(choice) > 1:
            continue

        if choice.lower() == "y" or choice == "":
            pay_now = True
            break

        if choice.lower() == "n":
            break

    if pay_now:
        # If they choose to pay now, attempt to create a payment, catching
        # any errors that occur (such as not having enough credits)
        print "  Creating payment..."
        try:
            payment = post(url(new_order['link'], 'payment/')).json
        except NotEnoughCreditsException:
            print "  You do not have enough available credits to pay for this Order."
            print "  To add credits to your account, please use the YippieMove website."
            print "  To pay for this order later using this utility, you should use:"
            print
            print "  $ ./yippiemove.py create payment order=%s" % new_order['id']
        else:
            print "  Payment of %s credits was successful." % payment['amount']
            print
            print "  Your jobs will start as soon as possible, but you can check on"
            print "  their status using the status subcommand:"
            print
            print "  $ ./yippiemove.py status order %s" % new_order['id']
    else:
        # If they choose not to pay now, tell them the Order ID and, to be
        # helpful, give them the CLI command they'll need to make payment later.
        print "  To pay later you'll need this Order's ID: %s" % new_order['id']
        print "  To pay using this utility, simply execute the following when you're ready:"
        print
        print "    $ ./yippiemove.py create payment order=%s" % new_order['link']
        print


################################################################
# Token management
################################################################

def get_token():
    """Attempts to retrieve the stored token,
    returning None if not available."""

    try:
        with open(".ymo_token", "r") as f:
            token = f.read()
        return token
    except:
        return None


def token_admin(action, token_string=None):
    """Handles the administration of getting, setting,
    and deleting a token."""

    if action == "set":
        if token_string is None:
            print "You must provide a token string."
            return

        try:
            with open(".ymo_token", "w") as f:
                f.write(token_string)
            print "Token set as %s" % token_string
        except IOError:
            print "Could not write token file."
        except:
            return

    elif action == "get":
        token = get_token()
        if token is not None:
            print "Token is: " + token
        else:
            print "Token is not set. Use yippiemove.py token set <token_string>"
            return None

    elif action == "delete":
        try:
            os.remove(".ymo_token")
            print "Token removed."
        except:
            print "Token could not be removed."

    elif action == "wizard":

        print "To obtain a token, please enter your application's public"
        print "and private keys."
        print

        CLIENT_KEY = raw_input(" Public Key: ")
        CLIENT_SECRET = raw_input("Private Key: ")

        parameters = {
            "client_id": CLIENT_KEY,
            "redirect_uri": get_oauth_url_for("access_code"),
            "response_type": "code"
        }

        print
        print "Please visit the following URL in your browser:"
        print
        print "    %s?%s" % (get_oauth_url_for("authorize"), urlencode(parameters))
        print
        print "When you've accepted and received your access code,"
        print "please enter it below:"
        ACCESS_CODE = raw_input("Access Code: ")

        parameters = {
            "client_id": CLIENT_KEY,
            "grant_type": "authorization_code",
            "code": ACCESS_CODE,
            "redirect_uri": get_oauth_url_for("access_code")
        }

        basic_auth = b64encode("%s:%s" % (CLIENT_KEY, CLIENT_SECRET))
        auth = HTTPBasicAuth(type_="Basic", data=basic_auth)
        try:
            response = requests.get("%s?%s" % (get_oauth_url_for("token"), urlencode(parameters)), auth=auth, verify=VERIFY_SSL)
            json = response.json
            token_admin("set", json['access_token'])
            print "Future actions you now take will use this access token by default."
        except:
            print "There was a problem retrieving your token. Please try again."


################################################################
# Main method
################################################################

def main(argv=None):

    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(description="Utility for managing YippieMove.")
    parser.add_argument("--api-url", dest="api_url", help="YippieMove API URL (default: %s)." % DEFAULT_API_SERVER, default=DEFAULT_API_SERVER)
    parser.add_argument("-t", "--token",    dest="token", help="YippieMove access token")
    parser.add_argument('-V', "--version",  action="version",   version="%(prog)s version " + VERSION)

    parser.add_argument('--log', metavar='LOGFILE', type=argparse.FileType('w'), default=sys.stderr, help='File to write log output to (default: stderr).')
    parser.add_argument('-v', '--verbose', action='append_const', const=True, help='Enable verbose logging. Specify twice for debug logging.')

    subparsers = parser.add_subparsers(title="Subcommands")

    parser_token = subparsers.add_parser("token", help="Commands for managing which access token to use.")
    parser_token.add_argument("action", help="Action to take", choices=["set", "get", "delete", "wizard"])
    parser_token.add_argument("token_string", help="The token string to set, if applicable.", nargs="?")
    parser_token.set_defaults(func=token_admin)

    parser_create = subparsers.add_parser("create", help="Create objects on YippieMove.")
    parser_create.add_argument("object_type", help="Type of object to be created.", choices=["move_job", "order", "payment", "batch", "email_account", "email_folder", "email_job", "component_job"])
    parser_create.add_argument("args",      help="Properties to be set on the new object, i.e. owner=2", nargs="*")
    parser_create.set_defaults(func=create)

    parser_read = subparsers.add_parser("read", help="Read objects from YippieMove.")
    parser_read.add_argument("object_type", help="Type of object to be read.", choices=["move_job", "order", "user", "payment", "batch", "email_account", "provider"])
    parser_read.add_argument("object_id", help="ID of object to read.")
    parser_read.add_argument("args",      help="GET arguments to be passed along, i.e. expand=move_job", nargs="*")
    parser_read.set_defaults(func=read)

    parser_update = subparsers.add_parser("update", help="Update objects on YippieMove.")
    parser_update.add_argument("object_type", help="Type of object to be updated.", choices=["move_job", "order", "batch", "email_account", "email_job", "component_job"])
    parser_update.add_argument("object_id", help="ID of object to update.")
    parser_update.add_argument("args",      help="Properties to be updated on the object, i.e. owner=2", nargs="+")
    parser_update.set_defaults(func=update)

    parser_delete = subparsers.add_parser("delete", help="Delete objects on YippieMove.")
    parser_delete.add_argument("object_type", help="Type of object to be deleted.", choices=["move_job", "order", "email_account"])
    parser_delete.add_argument("object_id", help="ID of object to delete.")
    parser_delete.add_argument("args",      help="Any required properties to locate object, i.e. move_job=2", nargs="*")
    parser_delete.set_defaults(func=remove)

    parser_list = subparsers.add_parser("list", help="List all objects of a given type on YippieMove.")
    parser_list.add_argument("object_type", help="Type of objects to list.", choices=["move_job", "order", "email_folder", "provider", "email_account"])
    parser_list.add_argument("args",      help="Arguments to use as filters.", nargs="*")
    parser_list.set_defaults(func=list_objects)

    parser_status = subparsers.add_parser("status", help="Display the status of an Order or MoveJob on YippieMove.")
    parser_status.add_argument("object_type", help="Type of object to get the status of.", choices=["order", "move_job"])
    parser_status.add_argument("object_id", help="ID of the object.")
    parser_status.set_defaults(func=status)

    parser_wizard = subparsers.add_parser("wizard", help="TODO")
    parser_wizard.add_argument("action", help="TODO", nargs="?")
    parser_wizard.set_defaults(func=wizard)

    args = parser.parse_args()

    global API_SERVER
    # FIXME Should we have two API globals?
    if args.api_url.endswith("/"):
        args.api_url = args.api_url[:-1]
    if not args.api_url.startswith("http"):  # if schema is missing, enforce https
        args.api_url = "https://%s" % args.api_url
    API_SERVER = args.api_url

    args = vars(args)

    # Make token globally accessible so we don't have to keep
    # passing it around.
    global API_ACCESS_TOKEN

    if not ("func" in args and args['func'] == token_admin):
        if args['token'] is not None:
            API_ACCESS_TOKEN = args['token']
        else:
            token = get_token()
            if token is None:
                logbook.error("You must specify a token before working with the YippieMove API.")
                return
            else:
                API_ACCESS_TOKEN = token

    try:
        if "func" in args:
            func = args['func']

            log_level = (logbook.WARNING, logbook.INFO, logbook.DEBUG)[min(2, len(args['verbose'] or []))]
            null_handler = logbook.NullHandler()
            with null_handler.applicationbound():
                with logbook.StreamHandler(args['log'], level=log_level, bubble=False) as log_handler:
                    with log_handler.applicationbound():
                        # Get rid of args we don't want to pass to the subcommand so that we can use **args.
                        for arg in ('token', 'api_url', 'verbose', 'log', 'func'):
                            if arg in args:
                                del args[arg]

                        result = func(**args)
                        if result:
                            print result

    except NotFoundException:
        logbook.error("The object you were looking for could not be found.")
    except NotAuthenticatedException:
        logbook.error("The token you provided was invalid. Please double-check your records.")
    except ForbiddenException:
        logbook.error("You do not have permission to perform the action you requested.")
    except MethodNotAllowedException:
        logbook.error("You are not allowed to perform that action on that object type.")
    except ServerErrorException:
        logbook.error("We're sorry, there was a problem on YippieMove's servers and your request could not be completed.")
    except ConflictException as e:
        logbook.error("We're sorry, there was a conflict: %s" % e)
    except BadRequestException, e:
        logbook.error("Could not complete your request: %s" % e.errors)


if __name__ == '__main__':

    main()
